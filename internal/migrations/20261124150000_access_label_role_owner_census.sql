-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Полный набор вопросов доступа по фактическим носителям защищённой роли.

-- +goose Up
SELECT kaname.authority_protocol_drain();

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_access_label_role_required_questions_v1(
 p_frozen jsonb,p_at timestamptz
) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE census jsonb;transition jsonb;expected_ids jsonb;scope jsonb;fallback jsonb;
 scopes jsonb:='[]';result jsonb;definition text;count_scopes integer;maximum bigint;
BEGIN
 IF p_at IS NULL OR NOT isfinite(p_at) OR p_frozen->>'mode' IS DISTINCT FROM 'access_label_transition'
 OR jsonb_typeof(p_frozen->'access_label_transition') IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_frozen->'access_label_scope_census') IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'required apply questions lack owner frozen census' USING ERRCODE='42501';END IF;
 census:=p_frozen->'access_label_scope_census';transition:=p_frozen->'access_label_transition';
 IF census-ARRAY['version','mode','complete','role_id','new_digest','new_definitions','scopes','fallback','max_questions'] IS DISTINCT FROM '{}'::jsonb
 OR census->'version' IS DISTINCT FROM '1'::jsonb OR census->'complete' IS DISTINCT FROM 'true'::jsonb
 OR census->>'role_id' IS DISTINCT FROM transition->>'role_id'
 OR coalesce(census->>'role_id','')=''
 OR census->>'new_digest' IS DISTINCT FROM transition->>'new_digest'
 OR coalesce(census->>'new_digest','') !~ '^[0-9a-f]{64}$'
 OR jsonb_typeof(transition->'new_projection') IS DISTINCT FROM 'array'
 OR jsonb_typeof(census->'new_definitions') IS DISTINCT FROM 'array'
 OR jsonb_typeof(census->'scopes') IS DISTINCT FROM 'array'
 OR jsonb_array_length(census->'scopes')>4096
 OR jsonb_array_length(transition->'new_projection')>16384 THEN
  RAISE EXCEPTION 'required apply questions census identity differs' USING ERRCODE='42501';END IF;
 SELECT coalesce(jsonb_agg(id ORDER BY id COLLATE "C"),'[]'::jsonb) INTO expected_ids
 FROM (SELECT DISTINCT e->>1 id FROM jsonb_array_elements(transition->'new_projection') e) d;
 IF census->'new_definitions' IS DISTINCT FROM expected_ids THEN
  RAISE EXCEPTION 'required apply definitions differ from owner NEW' USING ERRCODE='42501';END IF;
 IF census->>'mode'='revoke' THEN
  IF expected_ids IS DISTINCT FROM '[]'::jsonb
   OR census->'scopes' IS DISTINCT FROM '[]'::jsonb OR census->'max_questions' IS DISTINCT FROM '0'::jsonb
   OR census->'fallback' IS DISTINCT FROM 'null'::jsonb
   OR jsonb_typeof(transition->'old_projection') IS DISTINCT FROM 'array'
   OR transition->'old_projection'='[]'::jsonb THEN
   RAISE EXCEPTION 'clean revoke carries positive questions' USING ERRCODE='42501';END IF;
  RETURN '[]'::jsonb;
 END IF;
 IF census->>'mode' IS DISTINCT FROM 'apply' OR expected_ids='[]'::jsonb
 OR jsonb_array_length(expected_ids)>2048
 OR (transition#>>'{new_row,is_system}')::boolean IS DISTINCT FROM false
 OR num_nonnulls(transition#>>'{new_row,account_id}',transition#>>'{new_row,project_id}')<>1
 OR transition#>>'{new_row,cluster_id}' IS NOT NULL THEN
  RAISE EXCEPTION 'required apply questions have unsupported role definition tier' USING ERRCODE='42501';END IF;
 fallback:=CASE WHEN nullif(transition#>>'{new_row,project_id}','') IS NOT NULL
  THEN jsonb_build_object('scope_kind','project','scope_id',transition#>>'{new_row,project_id}')
  ELSE jsonb_build_object('scope_kind','account','scope_id',transition#>>'{new_row,account_id}') END;
 IF census->'fallback' IS DISTINCT FROM fallback OR coalesce(fallback->>'scope_id','')=''
 OR (fallback->>'scope_id')~'[:#*[:space:][:cntrl:]]' THEN
  RAISE EXCEPTION 'required apply fallback differs from role definition tier' USING ERRCODE='42501';END IF;
 maximum:=(jsonb_array_length(census->'scopes')::bigint+1)*jsonb_array_length(expected_ids);
 IF maximum>4096 OR census->'max_questions' IS DISTINCT FROM to_jsonb(maximum) THEN
  RAISE EXCEPTION 'required apply matrix exceeds prepaid bound' USING ERRCODE='54000';END IF;
 FOR scope IN SELECT value FROM jsonb_array_elements(census->'scopes') LOOP
  IF jsonb_typeof(scope) IS DISTINCT FROM 'object'
  OR scope-ARRAY['scope_kind','scope_id','never','max_expiry','bad_never','bad_max_expiry'] IS DISTINCT FROM '{}'::jsonb
  OR jsonb_typeof(scope->'never') IS DISTINCT FROM 'boolean'
  OR jsonb_typeof(scope->'bad_never') IS DISTINCT FROM 'boolean'
  OR NOT (scope ?& ARRAY['scope_kind','scope_id','max_expiry','bad_max_expiry'])
  OR jsonb_typeof(scope->'max_expiry') NOT IN ('null','string')
  OR jsonb_typeof(scope->'bad_max_expiry') NOT IN ('null','string') THEN
   RAISE EXCEPTION 'required apply scope census shape invalid' USING ERRCODE='42501';END IF;
  -- Каждый bucket создан хотя бы одним carrier: false+NULL не доказывает
  -- отсутствие живой области. Некорректная часть обязана быть подмножеством.
  IF (NOT (scope->>'never')::boolean AND scope->'max_expiry'='null'::jsonb)
   OR ((scope->>'bad_never')::boolean AND NOT (scope->>'never')::boolean)
   OR (scope->'bad_max_expiry'<>'null'::jsonb AND (scope->'max_expiry'='null'::jsonb
     OR (scope->>'bad_max_expiry')::timestamptz>(scope->>'max_expiry')::timestamptz)) THEN
   RAISE EXCEPTION 'required apply scope expiry census is uncertain' USING ERRCODE='42501';END IF;
  -- Некорректный carrier не исчезает из census из-за target/scope filtering.
  IF (scope->>'bad_never')::boolean OR (scope->>'bad_max_expiry')::timestamptz>p_at THEN
   RAISE EXCEPTION 'live role apply carrier has unsupported target or scope' USING ERRCODE='23514';END IF;
  IF (scope->>'never')::boolean OR (scope->>'max_expiry')::timestamptz>p_at THEN
   IF scope->>'scope_kind' IS NULL OR scope->>'scope_kind' NOT IN ('account','project')
    OR coalesce(scope->>'scope_id','')='' OR (scope->>'scope_id')~'[:#*[:space:][:cntrl:]]' THEN
    RAISE EXCEPTION 'required apply carrier scope invalid' USING ERRCODE='23514';END IF;
   scopes:=scopes||jsonb_build_array(jsonb_build_object('scope_kind',scope->>'scope_kind','scope_id',scope->>'scope_id'));
  END IF;
 END LOOP;
 IF scopes='[]'::jsonb THEN scopes:=jsonb_build_array(fallback);END IF;
 SELECT count(DISTINCT value)::integer INTO count_scopes FROM jsonb_array_elements(scopes);
 IF count_scopes<>jsonb_array_length(scopes) THEN
  RAISE EXCEPTION 'required apply scope census contains duplicates' USING ERRCODE='42501';END IF;
 FOR definition IN SELECT value FROM jsonb_array_elements_text(expected_ids) LOOP
  IF definition IS NULL OR definition IS DISTINCT FROM (definition::uuid)::text
   OR definition='00000000-0000-0000-0000-000000000000' THEN
   RAISE EXCEPTION 'required apply definition is not canonical' USING ERRCODE='23514';END IF;
  FOR scope IN SELECT value FROM jsonb_array_elements(scopes) LOOP
   IF transition#>>ARRAY['definition_witnesses',definition,'scope_kind'] IS DISTINCT FROM scope->>'scope_kind'
    OR transition#>>ARRAY['definition_witnesses',definition,'scope_id'] IS DISTINCT FROM scope->>'scope_id' THEN
    RAISE EXCEPTION 'required apply definition differs from complete role carrier scope' USING ERRCODE='42501';END IF;
  END LOOP;
 END LOOP;
 SELECT jsonb_agg(jsonb_build_object('scope_kind',s->>'scope_kind','scope_id',s->>'scope_id','definition_id',d)
   ORDER BY (s->>'scope_kind') COLLATE "C",(s->>'scope_id') COLLATE "C",d COLLATE "C")
 INTO result FROM jsonb_array_elements(scopes) s CROSS JOIN jsonb_array_elements_text(expected_ids) d;
 IF result IS NULL OR jsonb_array_length(result)>maximum THEN
  RAISE EXCEPTION 'required apply question matrix incomplete' USING ERRCODE='42501';END IF;
 RETURN result;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $access_label_role_census_private$
DECLARE grantee record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 REVOKE ALL ON FUNCTION kaname.authority_access_label_role_required_questions_v1(jsonb,timestamptz) FROM PUBLIC;
 FOR grantee IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a
  JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname.authority_access_label_role_required_questions_v1(jsonb,timestamptz)'::regprocedure AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.authority_access_label_role_required_questions_v1(jsonb,timestamptz) FROM %I',grantee.rolname);
 END LOOP;
END
$access_label_role_census_private$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $access_label_role_owner_census$
DECLARE
    item record;
    replacement jsonb;
    fn regprocedure;
    old_body text;
    new_body text;
    definition text;
    needle text;
BEGIN
    IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
        RAISE EXCEPTION 'несогласованное состояние перед подготовкой обязательных проверок accessLabels' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
        ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','1fee16aa90e9b764520158013479315184116fc5e17991573dac4f509f1fa0dc','cced8e3de809419c6506a4cca501c99bd5b4f4c465681bdb87261777bdbe4972',$patch$[[" retier boolean;creation boolean;promote boolean;side_name text;event_type text;\n scanned integer:=1;reads integer:=1;carriers integer:=0;\n access_label_transition jsonb;access_label_frozen jsonb:='{}';access_label_needed boolean;\n access_label_authority_input jsonb;access_label_authority jsonb;\nBEGIN\n proof:=kaname.authority_protocol_attestation();\n", " retier boolean;creation boolean;promote boolean;side_name text;event_type text;\n scanned integer:=1;reads integer:=1;carriers integer:=0;\n access_label_transition jsonb;access_label_frozen jsonb:='{}';access_label_needed boolean;\n access_label_scope_needed boolean:=false;scope_rollup jsonb:='{}';scope_count integer:=0;\n carrier_source record;scope_key text;scope_state jsonb;scope_valid boolean;\n carrier_expiry timestamptz;scope_ids jsonb;scope_values jsonb;fallback_scope jsonb;\n scope_maximum bigint;scope_cost bigint;\n access_label_authority_input jsonb;access_label_authority jsonb;\nBEGIN\n proof:=kaname.authority_protocol_attestation();\n"], ["  root_stamp:=greatest(root_stamp,(old_role->>'created_at')::timestamptz);\n  IF jsonb_array_length(mask)>0 THEN new_role:=new_role||jsonb_build_object('updated_at',root_stamp);END IF;\n END IF;\n IF old_role IS DISTINCT FROM new_role THEN\n  ordinal:=ordinal+1;\n  origin:=jsonb_build_object('table','roles','operation',CASE WHEN creation THEN 'INSERT' ELSE 'UPDATE' END,\n", "  root_stamp:=greatest(root_stamp,(old_role->>'created_at')::timestamptz);\n  IF jsonb_array_length(mask)>0 THEN new_role:=new_role||jsonb_build_object('updated_at',root_stamp);END IF;\n END IF;\n -- Scope census нужен для новой explicit apply authoring, включая повторную\n -- отправку тех же rules. Metadata-only не включает этот lane.\n IF creation OR promote THEN\n  SELECT EXISTS(SELECT 1 FROM jsonb_array_elements(new_role->'rules') r\n   WHERE r->>'module'='iam' AND r->'resources' ? 'accessLabel' AND r->'verbs' ? 'apply')\n  INTO access_label_scope_needed;\n END IF;\n IF old_role IS DISTINCT FROM new_role THEN\n  ordinal:=ordinal+1;\n  origin:=jsonb_build_object('table','roles','operation',CASE WHEN creation THEN 'INSERT' ELSE 'UPDATE' END,\n"], ["   'origin',jsonb_build_object('family','role.create','role',new_role->>'id'),'row',row_value,'stamp','transaction'));\n END IF;\n IF NOT creation AND promote THEN\n  FOR carrier IN SELECT to_jsonb(b) FROM kaname.access_bindings b WHERE b.role_id=new_role->>'id' ORDER BY b.id COLLATE \"C\" LIMIT 100001 LOOP\n   carriers:=carriers+1;scanned:=scanned+1;\n   IF carriers>p_rows OR scanned>p_rows OR jsonb_array_length(maximum)>100000 THEN RAISE EXCEPTION 'role sequence population bound' USING ERRCODE='54000';END IF;\n   IF retier AND carrier->>'status'<>'REVOKED' THEN\n    SELECT coalesce(jsonb_agg(jsonb_build_object('user',t.fga_user,'relation',t.relation,'object',t.object)\n     ORDER BY t.object COLLATE \"C\",t.fga_user COLLATE \"C\",t.relation COLLATE \"C\"),'[]') INTO old_tuples\n", "   'origin',jsonb_build_object('family','role.create','role',new_role->>'id'),'row',row_value,'stamp','transaction'));\n END IF;\n IF NOT creation AND promote THEN\n  -- Тот же единственный census; project lookup нужен только positive apply.\n  -- У projects.id один PK: join не размножает carriers.\n  FOR carrier_source IN SELECT to_jsonb(b) AS binding,p.account_id AS project_account\n   FROM kaname.access_bindings b LEFT JOIN LATERAL (\n    SELECT p.account_id FROM kaname.projects p\n    WHERE access_label_scope_needed AND b.status IN ('ACTIVE','PENDING') AND b.revoked_at IS NULL\n     AND b.resource_type='project' AND p.id=b.resource_id FOR SHARE OF p\n   ) p ON true\n   WHERE b.role_id=new_role->>'id' ORDER BY b.id COLLATE \"C\" LIMIT 100001 LOOP\n   carrier:=carrier_source.binding;\n   carriers:=carriers+1;scanned:=scanned+1;\n   IF carriers>p_rows OR scanned>p_rows OR jsonb_array_length(maximum)>100000 THEN RAISE EXCEPTION 'role sequence population bound' USING ERRCODE='54000';END IF;\n   IF access_label_scope_needed AND carrier->>'status' IN ('ACTIVE','PENDING')\n    AND carrier->'revoked_at'='null'::jsonb THEN\n    -- Не фильтруем target/scope: живой непригодный carrier запрещает NEW apply.\n    -- Расход project lookup учитывается вместе с уже начисленной строкой b.\n    IF carrier->>'resource_type'='project' THEN scanned:=scanned+1;END IF;\n    IF scanned>p_rows THEN RAISE EXCEPTION 'role apply scope census budget' USING ERRCODE='54000';END IF;\n    scope_key:=jsonb_build_array(carrier->>'resource_type',carrier->>'resource_id')::text;\n    scope_state:=scope_rollup->scope_key;\n    IF scope_state IS NULL THEN\n     scope_count:=scope_count+1;\n     IF scope_count>4096 THEN RAISE EXCEPTION 'role apply scope census bound' USING ERRCODE='54000';END IF;\n     scope_state:=jsonb_build_object('scope_kind',carrier->>'resource_type','scope_id',carrier->>'resource_id',\n      'never',false,'max_expiry',NULL,'bad_never',false,'bad_max_expiry',NULL);\n    END IF;\n    scope_valid:=coalesce(\n     carrier->>'resource_type' IN ('account','project') AND coalesce(carrier->>'resource_id','')<>''\n     AND (carrier->>'resource_id')!~'[:#*[:space:][:cntrl:]]'\n     AND jsonb_typeof(carrier->'target')='object'\n     AND (NOT (carrier->'target' ? 'allInScope') OR jsonb_typeof(carrier#>'{target,allInScope}')='boolean')\n     AND (NOT (carrier->'target' ? 'resources') OR carrier#>'{target,resources}'='[]'::jsonb)\n     AND ((nullif(new_role->>'project_id','') IS NOT NULL\n       AND carrier->>'resource_type'='project' AND carrier->>'resource_id'=new_role->>'project_id')\n      OR (nullif(new_role->>'project_id','') IS NULL AND nullif(new_role->>'account_id','') IS NOT NULL\n       AND ((carrier->>'resource_type'='account' AND carrier->>'resource_id'=new_role->>'account_id')\n        OR (carrier->>'resource_type'='project' AND carrier_source.project_account=new_role->>'account_id')))),false);\n    carrier_expiry:=(carrier->>'expires_at')::timestamptz;\n    IF carrier_expiry IS NULL THEN\n     scope_state:=scope_state||jsonb_build_object('never',true);\n     IF NOT scope_valid THEN scope_state:=scope_state||jsonb_build_object('bad_never',true);END IF;\n    ELSE\n     scope_state:=scope_state||jsonb_build_object('max_expiry',greatest(carrier_expiry,(scope_state->>'max_expiry')::timestamptz));\n     IF NOT scope_valid THEN scope_state:=scope_state||jsonb_build_object('bad_max_expiry',greatest(carrier_expiry,(scope_state->>'bad_max_expiry')::timestamptz));END IF;\n    END IF;\n    scope_rollup:=jsonb_set(scope_rollup,ARRAY[scope_key],scope_state,true);\n   END IF;\n   IF retier AND carrier->>'status'<>'REVOKED' THEN\n    SELECT coalesce(jsonb_agg(jsonb_build_object('user',t.fga_user,'relation',t.relation,'object',t.object)\n     ORDER BY t.object COLLATE \"C\",t.fga_user COLLATE \"C\",t.relation COLLATE \"C\"),'[]') INTO old_tuples\n"], [" scanned:=scanned+jsonb_array_length(maximum);reads:=reads+2;\n IF scanned>p_rows OR reads>p_reads THEN RAISE EXCEPTION 'role sequence program budget' USING ERRCODE='54000';END IF;\n -- Проверяем изменение по фактическим образам роли.\n IF creation OR old_role->'rules' IS DISTINCT FROM new_role->'rules' THEN\n  -- Прежние правила без этой оси сохраняют свой формат и пределы.\n  -- Сохранённая проекция требует сверки даже при пустой новой стороне.\n  SELECT EXISTS(SELECT 1\n", " scanned:=scanned+jsonb_array_length(maximum);reads:=reads+2;\n IF scanned>p_rows OR reads>p_reads THEN RAISE EXCEPTION 'role sequence program budget' USING ERRCODE='54000';END IF;\n -- Проверяем изменение по фактическим образам роли.\n IF creation OR old_role->'rules' IS DISTINCT FROM new_role->'rules' OR access_label_scope_needed THEN\n  -- Прежние правила без этой оси сохраняют свой формат и пределы.\n  -- Сохранённая проекция требует сверки даже при пустой новой стороне.\n  SELECT EXISTS(SELECT 1\n"], ["   IF access_label_needed THEN scanned:=scanned+1;END IF;\n  END IF;\n  IF access_label_needed THEN\n   access_label_transition:=kaname.authority_access_label_role_transition_prepare_v1(\n    old_role,new_role,p_rows-scanned,p_reads-reads);\n   scanned:=scanned+(access_label_transition->>'rows')::integer;\n", "   IF access_label_needed THEN scanned:=scanned+1;END IF;\n  END IF;\n  IF access_label_needed THEN\n   IF NOT creation AND NOT promote THEN\n    RAISE EXCEPTION 'protected role rules change lacks carrier census' USING ERRCODE='42501';\n   END IF;\n   access_label_transition:=kaname.authority_access_label_role_transition_prepare_v1(\n    old_role,new_role,p_rows-scanned,p_reads-reads);\n   scanned:=scanned+(access_label_transition->>'rows')::integer;\n"], ["    OR access_label_transition->'new_projection'<>'[]'::jsonb THEN\n    access_label_frozen:=jsonb_build_object('mode','access_label_transition',\n     'access_label_transition',access_label_transition);\n    IF access_label_authority IS NOT NULL THEN\n     access_label_frozen:=access_label_frozen||jsonb_build_object('access_label_authority',access_label_authority);\n    END IF;\n", "    OR access_label_transition->'new_projection'<>'[]'::jsonb THEN\n    access_label_frozen:=jsonb_build_object('mode','access_label_transition',\n     'access_label_transition',access_label_transition);\n    IF access_label_transition->'new_projection'='[]'::jsonb THEN\n     -- Clean revoke не требует apply authority или fallback expansion.\n     access_label_frozen:=access_label_frozen||jsonb_build_object('access_label_scope_census',\n      jsonb_build_object('version',1,'mode','revoke','complete',true,'role_id',new_role->>'id',\n       'new_digest',access_label_transition->>'new_digest','new_definitions','[]'::jsonb,'scopes','[]'::jsonb,\n       'fallback',NULL,'max_questions',0));\n    ELSE\n     IF NOT access_label_scope_needed OR (NOT creation AND NOT promote)\n      OR (new_role->>'is_system')::boolean IS DISTINCT FROM false\n      OR num_nonnulls(new_role->>'account_id',new_role->>'project_id')<>1\n      OR new_role->>'cluster_id' IS NOT NULL THEN\n      RAISE EXCEPTION 'role apply scope census is incomplete or definition tier unsupported' USING ERRCODE='42501';END IF;\n     fallback_scope:=CASE WHEN nullif(new_role->>'project_id','') IS NOT NULL\n      THEN jsonb_build_object('scope_kind','project','scope_id',new_role->>'project_id')\n      ELSE jsonb_build_object('scope_kind','account','scope_id',new_role->>'account_id') END;\n     SELECT coalesce(jsonb_agg(id ORDER BY id COLLATE \"C\"),'[]'::jsonb) INTO scope_ids\n      FROM (SELECT DISTINCT e->>1 id FROM jsonb_array_elements(access_label_transition->'new_projection') e) d;\n     SELECT coalesce(jsonb_agg(value ORDER BY (value->>'scope_kind') COLLATE \"C\",(value->>'scope_id') COLLATE \"C\"),'[]'::jsonb)\n      INTO scope_values FROM jsonb_each(scope_rollup);\n     scope_maximum:=(scope_count::bigint+1)*jsonb_array_length(scope_ids);\n     -- Prepay весь возможный final matrix, включая fallback при expiry всех.\n     -- finalize не выполняет business reads и не получает новый бюджет.\n     scope_cost:=2+scope_count::bigint+jsonb_array_length(scope_ids)+2*scope_maximum;\n     IF scope_maximum>4096 OR scope_cost>p_rows-scanned THEN\n      RAISE EXCEPTION 'role apply required matrix budget' USING ERRCODE='54000';END IF;\n     scanned:=scanned+scope_cost::integer;\n     reads:=reads+1; -- owner finalization of required questions\n     access_label_frozen:=access_label_frozen||jsonb_build_object('access_label_scope_census',\n      jsonb_build_object('version',1,'mode','apply','complete',true,'role_id',new_role->>'id',\n       'new_digest',access_label_transition->>'new_digest','new_definitions',scope_ids,\n       'scopes',scope_values,'fallback',fallback_scope,'max_questions',scope_maximum));\n    END IF;\n    IF access_label_authority IS NOT NULL THEN\n     access_label_frozen:=access_label_frozen||jsonb_build_object('access_label_authority',access_label_authority);\n    END IF;\n"]]$patch$::jsonb),
        ('authority_role_sequence_finalize_v3()','4b1b5626bc90a7826a4bed308befc83c4e688b636f9dcd59d7446811f20ec891','22ea6d68eec1c2e597666316ba4614f4f225f96433561884e412c71476b48146',$patch$[["DECLARE program jsonb;proof jsonb;ordinals integer[];at_time timestamptz;", "DECLARE program jsonb;proof jsonb;ordinals integer[];at_time timestamptz;\n required_questions jsonb;required_index jsonb;"], [" PERFORM kaname._authority_sequence_select_v3(ordinals,at_time);", " PERFORM kaname._authority_sequence_select_v3(ordinals,at_time);\n IF program#>>'{frozen,mode}'='access_label_transition'\n AND program#>>'{frozen,access_label_scope_census,mode}'='apply' THEN\n  required_questions:=kaname.authority_access_label_role_required_questions_v1(program->'frozen',at_time);\n  SELECT jsonb_object_agg(\n    jsonb_build_array(q->>'scope_kind',q->>'scope_id',q->>'definition_id')::text,true)\n   INTO required_index FROM jsonb_array_elements(required_questions) q;\n  IF required_index IS NULL OR required_index='{}'::jsonb THEN\n   RAISE EXCEPTION 'role access label finalized question set is empty' USING ERRCODE='42501';END IF;\n  UPDATE pg_temp.kaname_authority_sequence_program s\n  SET frozen=s.frozen||jsonb_build_object('access_label_required_questions',required_questions,\n   'access_label_required_index',required_index)\n  WHERE s.singleton AND s.nonce=(proof->>'nonce')::uuid AND s.decision_at=at_time\n   AND s.frozen_mode='access_label_transition'\n   AND NOT (s.frozen ? 'access_label_required_questions');\n  IF NOT FOUND THEN\n   RAISE EXCEPTION 'role access label finalized question program differs' USING ERRCODE='42501';END IF;\n END IF;"]]$patch$::jsonb),
        ('authority_access_label_role_question_require_v1(text,text,text,text,uuid,integer,integer)','a5b7081e9cd8901c88132ba503e9006923c21fca16d366913de540bb8e11cd3c','8790c6de466bd69d3f9430dd7061cb68fc3f856b89b7f0ddd4756c49d1086eb8',$patch$[["mutation_id text;new_digest text;own_role_written boolean;question_key text;", "mutation_id text;new_digest text;own_role_written boolean;question_key text;required_index jsonb;"], [" SELECT s.frozen->'access_label_authority',s.decision_at,s.staged_decision_at,", " SELECT s.frozen->'access_label_authority',s.frozen->'access_label_required_index',s.decision_at,s.staged_decision_at,"], [" INTO receipt,selected_at,prepared_at,mutation_id,new_digest,own_role_written", " INTO receipt,required_index,selected_at,prepared_at,mutation_id,new_digest,own_role_written"], [" IF (receipt->'questions')->question_key IS DISTINCT FROM 'true'::jsonb THEN", " IF required_index->question_key IS DISTINCT FROM 'true'::jsonb\n OR (receipt->'questions')->question_key IS DISTINCT FROM 'true'::jsonb THEN"]]$patch$::jsonb),
        ('_authority_crud_storage_v3()','fbfa3a661ed99588248fbe8a4915bfc33561cb6088aa59ada2aa57c19c5fe7c2','af16eec6744d6427770490df72f9f362cf85008aed5e0152d6c1d78c6ab45e0b',$patch$[[" ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','1fee16aa90e9b764520158013479315184116fc5e17991573dac4f509f1fa0dc',true,'v',true,'export'),", " ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','cced8e3de809419c6506a4cca501c99bd5b4f4c465681bdb87261777bdbe4972',true,'v',true,'export'),"], [" ('authority_role_sequence_finalize_v3()','4b1b5626bc90a7826a4bed308befc83c4e688b636f9dcd59d7446811f20ec891',true,'v',true,'export'),", " ('authority_role_sequence_finalize_v3()','22ea6d68eec1c2e597666316ba4614f4f225f96433561884e412c71476b48146',true,'v',true,'export'),"], [" ('authority_access_label_role_question_require_v1(text,text,text,text,uuid,integer,integer)','a5b7081e9cd8901c88132ba503e9006923c21fca16d366913de540bb8e11cd3c',false,'v',true,'private'),", " ('authority_access_label_role_question_require_v1(text,text,text,text,uuid,integer,integer)','8790c6de466bd69d3f9430dd7061cb68fc3f856b89b7f0ddd4756c49d1086eb8',false,'v',true,'private'),"], [" ('authority_access_label_role_question_require_v1(text,text,text,text,uuid,integer,integer)','8790c6de466bd69d3f9430dd7061cb68fc3f856b89b7f0ddd4756c49d1086eb8',false,'v',true,'private'),", " ('authority_access_label_role_question_require_v1(text,text,text,text,uuid,integer,integer)','8790c6de466bd69d3f9430dd7061cb68fc3f856b89b7f0ddd4756c49d1086eb8',false,'v',true,'private'),\n ('authority_access_label_role_required_questions_v1(jsonb,timestamptz)','cecd16df03cc470ed62f32f50deac22a0b8bf2468f06d2e8610f6fa4f938730e',false,'s',true,'private'),"]]$patch$::jsonb),
        ('_authority_full_contract_storage_v3()','cdc3716469a20f6dcb0f23eec48dbbe3a80220ec0863ddce866caf253c022728','0238b319dfa2d10808f1e0b4972693863a74b42845bae565f69774b54626f46f',$patch$[["fbfa3a661ed99588248fbe8a4915bfc33561cb6088aa59ada2aa57c19c5fe7c2", "af16eec6744d6427770490df72f9f362cf85008aed5e0152d6c1d78c6ab45e0b"]]$patch$::jsonb)
    ) AS changes(signature, before_sha, after_sha, substitutions) LOOP
        fn := pg_catalog.to_regprocedure('kaname.' || item.signature);
        IF fn IS NULL THEN RAISE EXCEPTION 'функция % для миграции отсутствует', item.signature USING ERRCODE='55000';END IF;
        SELECT p.prosrc INTO STRICT old_body FROM pg_catalog.pg_proc p WHERE p.oid=fn;
        IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(old_body,'UTF8')),'hex') IS DISTINCT FROM item.before_sha THEN
            RAISE EXCEPTION 'исходное тело функции % не соответствует этой миграции', item.signature USING ERRCODE='55000';
        END IF;
        new_body := old_body;
        FOR replacement IN SELECT value FROM pg_catalog.jsonb_array_elements(item.substitutions) LOOP
            needle := replacement->>0;
            IF length(new_body)-length(replace(new_body,needle,'')) IS DISTINCT FROM length(needle) THEN
                RAISE EXCEPTION 'фрагмент тела функции % не уникален', item.signature USING ERRCODE='55000';
            END IF;
            new_body := replace(new_body,needle,replacement->>1);
        END LOOP;
        IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(new_body,'UTF8')),'hex') IS DISTINCT FROM item.after_sha THEN
            RAISE EXCEPTION 'расчётное тело функции % изменилось', item.signature USING ERRCODE='55000';
        END IF;
        -- PostgreSQL восстанавливает сигнатуру и настройки, CREATE OR REPLACE
        -- сохраняет owner/ACL. Меняется ровно одно полное тело с известным SHA.
        definition := pg_catalog.pg_get_functiondef(fn);
        IF length(definition)-length(replace(definition,old_body,'')) IS DISTINCT FROM length(old_body) THEN
            RAISE EXCEPTION 'определение функции % не содержит единственного исходного тела', item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,old_body,new_body);
        IF (SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc,'UTF8')),'hex')
            FROM pg_catalog.pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.after_sha THEN
            RAISE EXCEPTION 'установленное тело функции % не совпадает с расчётным', item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
        RAISE EXCEPTION 'несогласованное состояние после подготовки обязательных проверок accessLabels' USING ERRCODE='55000';
    END IF;
END
$access_label_role_owner_census$;
-- +goose StatementEnd


-- +goose Down
SELECT kaname.authority_protocol_drain();

-- +goose StatementBegin
DO $access_label_role_owner_census$
DECLARE
    item record;
    replacement jsonb;
    fn regprocedure;
    old_body text;
    new_body text;
    definition text;
    needle text;
BEGIN
    IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
        RAISE EXCEPTION 'несогласованное состояние перед подготовкой обязательных проверок accessLabels' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
        ('_authority_full_contract_storage_v3()','0238b319dfa2d10808f1e0b4972693863a74b42845bae565f69774b54626f46f','cdc3716469a20f6dcb0f23eec48dbbe3a80220ec0863ddce866caf253c022728',$patch$[["af16eec6744d6427770490df72f9f362cf85008aed5e0152d6c1d78c6ab45e0b", "fbfa3a661ed99588248fbe8a4915bfc33561cb6088aa59ada2aa57c19c5fe7c2"]]$patch$::jsonb),
        ('_authority_crud_storage_v3()','af16eec6744d6427770490df72f9f362cf85008aed5e0152d6c1d78c6ab45e0b','fbfa3a661ed99588248fbe8a4915bfc33561cb6088aa59ada2aa57c19c5fe7c2',$patch$[[" ('authority_access_label_role_question_require_v1(text,text,text,text,uuid,integer,integer)','8790c6de466bd69d3f9430dd7061cb68fc3f856b89b7f0ddd4756c49d1086eb8',false,'v',true,'private'),\n ('authority_access_label_role_required_questions_v1(jsonb,timestamptz)','cecd16df03cc470ed62f32f50deac22a0b8bf2468f06d2e8610f6fa4f938730e',false,'s',true,'private'),", " ('authority_access_label_role_question_require_v1(text,text,text,text,uuid,integer,integer)','8790c6de466bd69d3f9430dd7061cb68fc3f856b89b7f0ddd4756c49d1086eb8',false,'v',true,'private'),"], [" ('authority_access_label_role_question_require_v1(text,text,text,text,uuid,integer,integer)','8790c6de466bd69d3f9430dd7061cb68fc3f856b89b7f0ddd4756c49d1086eb8',false,'v',true,'private'),", " ('authority_access_label_role_question_require_v1(text,text,text,text,uuid,integer,integer)','a5b7081e9cd8901c88132ba503e9006923c21fca16d366913de540bb8e11cd3c',false,'v',true,'private'),"], [" ('authority_role_sequence_finalize_v3()','22ea6d68eec1c2e597666316ba4614f4f225f96433561884e412c71476b48146',true,'v',true,'export'),", " ('authority_role_sequence_finalize_v3()','4b1b5626bc90a7826a4bed308befc83c4e688b636f9dcd59d7446811f20ec891',true,'v',true,'export'),"], [" ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','cced8e3de809419c6506a4cca501c99bd5b4f4c465681bdb87261777bdbe4972',true,'v',true,'export'),", " ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','1fee16aa90e9b764520158013479315184116fc5e17991573dac4f509f1fa0dc',true,'v',true,'export'),"]]$patch$::jsonb),
        ('authority_access_label_role_question_require_v1(text,text,text,text,uuid,integer,integer)','8790c6de466bd69d3f9430dd7061cb68fc3f856b89b7f0ddd4756c49d1086eb8','a5b7081e9cd8901c88132ba503e9006923c21fca16d366913de540bb8e11cd3c',$patch$[[" IF required_index->question_key IS DISTINCT FROM 'true'::jsonb\n OR (receipt->'questions')->question_key IS DISTINCT FROM 'true'::jsonb THEN", " IF (receipt->'questions')->question_key IS DISTINCT FROM 'true'::jsonb THEN"], [" INTO receipt,required_index,selected_at,prepared_at,mutation_id,new_digest,own_role_written", " INTO receipt,selected_at,prepared_at,mutation_id,new_digest,own_role_written"], [" SELECT s.frozen->'access_label_authority',s.frozen->'access_label_required_index',s.decision_at,s.staged_decision_at,", " SELECT s.frozen->'access_label_authority',s.decision_at,s.staged_decision_at,"], ["mutation_id text;new_digest text;own_role_written boolean;question_key text;required_index jsonb;", "mutation_id text;new_digest text;own_role_written boolean;question_key text;"]]$patch$::jsonb),
        ('authority_role_sequence_finalize_v3()','22ea6d68eec1c2e597666316ba4614f4f225f96433561884e412c71476b48146','4b1b5626bc90a7826a4bed308befc83c4e688b636f9dcd59d7446811f20ec891',$patch$[[" PERFORM kaname._authority_sequence_select_v3(ordinals,at_time);\n IF program#>>'{frozen,mode}'='access_label_transition'\n AND program#>>'{frozen,access_label_scope_census,mode}'='apply' THEN\n  required_questions:=kaname.authority_access_label_role_required_questions_v1(program->'frozen',at_time);\n  SELECT jsonb_object_agg(\n    jsonb_build_array(q->>'scope_kind',q->>'scope_id',q->>'definition_id')::text,true)\n   INTO required_index FROM jsonb_array_elements(required_questions) q;\n  IF required_index IS NULL OR required_index='{}'::jsonb THEN\n   RAISE EXCEPTION 'role access label finalized question set is empty' USING ERRCODE='42501';END IF;\n  UPDATE pg_temp.kaname_authority_sequence_program s\n  SET frozen=s.frozen||jsonb_build_object('access_label_required_questions',required_questions,\n   'access_label_required_index',required_index)\n  WHERE s.singleton AND s.nonce=(proof->>'nonce')::uuid AND s.decision_at=at_time\n   AND s.frozen_mode='access_label_transition'\n   AND NOT (s.frozen ? 'access_label_required_questions');\n  IF NOT FOUND THEN\n   RAISE EXCEPTION 'role access label finalized question program differs' USING ERRCODE='42501';END IF;\n END IF;", " PERFORM kaname._authority_sequence_select_v3(ordinals,at_time);"], ["DECLARE program jsonb;proof jsonb;ordinals integer[];at_time timestamptz;\n required_questions jsonb;required_index jsonb;", "DECLARE program jsonb;proof jsonb;ordinals integer[];at_time timestamptz;"]]$patch$::jsonb),
        ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','cced8e3de809419c6506a4cca501c99bd5b4f4c465681bdb87261777bdbe4972','1fee16aa90e9b764520158013479315184116fc5e17991573dac4f509f1fa0dc',$patch$[["    OR access_label_transition->'new_projection'<>'[]'::jsonb THEN\n    access_label_frozen:=jsonb_build_object('mode','access_label_transition',\n     'access_label_transition',access_label_transition);\n    IF access_label_transition->'new_projection'='[]'::jsonb THEN\n     -- Clean revoke не требует apply authority или fallback expansion.\n     access_label_frozen:=access_label_frozen||jsonb_build_object('access_label_scope_census',\n      jsonb_build_object('version',1,'mode','revoke','complete',true,'role_id',new_role->>'id',\n       'new_digest',access_label_transition->>'new_digest','new_definitions','[]'::jsonb,'scopes','[]'::jsonb,\n       'fallback',NULL,'max_questions',0));\n    ELSE\n     IF NOT access_label_scope_needed OR (NOT creation AND NOT promote)\n      OR (new_role->>'is_system')::boolean IS DISTINCT FROM false\n      OR num_nonnulls(new_role->>'account_id',new_role->>'project_id')<>1\n      OR new_role->>'cluster_id' IS NOT NULL THEN\n      RAISE EXCEPTION 'role apply scope census is incomplete or definition tier unsupported' USING ERRCODE='42501';END IF;\n     fallback_scope:=CASE WHEN nullif(new_role->>'project_id','') IS NOT NULL\n      THEN jsonb_build_object('scope_kind','project','scope_id',new_role->>'project_id')\n      ELSE jsonb_build_object('scope_kind','account','scope_id',new_role->>'account_id') END;\n     SELECT coalesce(jsonb_agg(id ORDER BY id COLLATE \"C\"),'[]'::jsonb) INTO scope_ids\n      FROM (SELECT DISTINCT e->>1 id FROM jsonb_array_elements(access_label_transition->'new_projection') e) d;\n     SELECT coalesce(jsonb_agg(value ORDER BY (value->>'scope_kind') COLLATE \"C\",(value->>'scope_id') COLLATE \"C\"),'[]'::jsonb)\n      INTO scope_values FROM jsonb_each(scope_rollup);\n     scope_maximum:=(scope_count::bigint+1)*jsonb_array_length(scope_ids);\n     -- Prepay весь возможный final matrix, включая fallback при expiry всех.\n     -- finalize не выполняет business reads и не получает новый бюджет.\n     scope_cost:=2+scope_count::bigint+jsonb_array_length(scope_ids)+2*scope_maximum;\n     IF scope_maximum>4096 OR scope_cost>p_rows-scanned THEN\n      RAISE EXCEPTION 'role apply required matrix budget' USING ERRCODE='54000';END IF;\n     scanned:=scanned+scope_cost::integer;\n     reads:=reads+1; -- owner finalization of required questions\n     access_label_frozen:=access_label_frozen||jsonb_build_object('access_label_scope_census',\n      jsonb_build_object('version',1,'mode','apply','complete',true,'role_id',new_role->>'id',\n       'new_digest',access_label_transition->>'new_digest','new_definitions',scope_ids,\n       'scopes',scope_values,'fallback',fallback_scope,'max_questions',scope_maximum));\n    END IF;\n    IF access_label_authority IS NOT NULL THEN\n     access_label_frozen:=access_label_frozen||jsonb_build_object('access_label_authority',access_label_authority);\n    END IF;\n", "    OR access_label_transition->'new_projection'<>'[]'::jsonb THEN\n    access_label_frozen:=jsonb_build_object('mode','access_label_transition',\n     'access_label_transition',access_label_transition);\n    IF access_label_authority IS NOT NULL THEN\n     access_label_frozen:=access_label_frozen||jsonb_build_object('access_label_authority',access_label_authority);\n    END IF;\n"], ["   IF access_label_needed THEN scanned:=scanned+1;END IF;\n  END IF;\n  IF access_label_needed THEN\n   IF NOT creation AND NOT promote THEN\n    RAISE EXCEPTION 'protected role rules change lacks carrier census' USING ERRCODE='42501';\n   END IF;\n   access_label_transition:=kaname.authority_access_label_role_transition_prepare_v1(\n    old_role,new_role,p_rows-scanned,p_reads-reads);\n   scanned:=scanned+(access_label_transition->>'rows')::integer;\n", "   IF access_label_needed THEN scanned:=scanned+1;END IF;\n  END IF;\n  IF access_label_needed THEN\n   access_label_transition:=kaname.authority_access_label_role_transition_prepare_v1(\n    old_role,new_role,p_rows-scanned,p_reads-reads);\n   scanned:=scanned+(access_label_transition->>'rows')::integer;\n"], [" scanned:=scanned+jsonb_array_length(maximum);reads:=reads+2;\n IF scanned>p_rows OR reads>p_reads THEN RAISE EXCEPTION 'role sequence program budget' USING ERRCODE='54000';END IF;\n -- Проверяем изменение по фактическим образам роли.\n IF creation OR old_role->'rules' IS DISTINCT FROM new_role->'rules' OR access_label_scope_needed THEN\n  -- Прежние правила без этой оси сохраняют свой формат и пределы.\n  -- Сохранённая проекция требует сверки даже при пустой новой стороне.\n  SELECT EXISTS(SELECT 1\n", " scanned:=scanned+jsonb_array_length(maximum);reads:=reads+2;\n IF scanned>p_rows OR reads>p_reads THEN RAISE EXCEPTION 'role sequence program budget' USING ERRCODE='54000';END IF;\n -- Проверяем изменение по фактическим образам роли.\n IF creation OR old_role->'rules' IS DISTINCT FROM new_role->'rules' THEN\n  -- Прежние правила без этой оси сохраняют свой формат и пределы.\n  -- Сохранённая проекция требует сверки даже при пустой новой стороне.\n  SELECT EXISTS(SELECT 1\n"], ["   'origin',jsonb_build_object('family','role.create','role',new_role->>'id'),'row',row_value,'stamp','transaction'));\n END IF;\n IF NOT creation AND promote THEN\n  -- Тот же единственный census; project lookup нужен только positive apply.\n  -- У projects.id один PK: join не размножает carriers.\n  FOR carrier_source IN SELECT to_jsonb(b) AS binding,p.account_id AS project_account\n   FROM kaname.access_bindings b LEFT JOIN LATERAL (\n    SELECT p.account_id FROM kaname.projects p\n    WHERE access_label_scope_needed AND b.status IN ('ACTIVE','PENDING') AND b.revoked_at IS NULL\n     AND b.resource_type='project' AND p.id=b.resource_id FOR SHARE OF p\n   ) p ON true\n   WHERE b.role_id=new_role->>'id' ORDER BY b.id COLLATE \"C\" LIMIT 100001 LOOP\n   carrier:=carrier_source.binding;\n   carriers:=carriers+1;scanned:=scanned+1;\n   IF carriers>p_rows OR scanned>p_rows OR jsonb_array_length(maximum)>100000 THEN RAISE EXCEPTION 'role sequence population bound' USING ERRCODE='54000';END IF;\n   IF access_label_scope_needed AND carrier->>'status' IN ('ACTIVE','PENDING')\n    AND carrier->'revoked_at'='null'::jsonb THEN\n    -- Не фильтруем target/scope: живой непригодный carrier запрещает NEW apply.\n    -- Расход project lookup учитывается вместе с уже начисленной строкой b.\n    IF carrier->>'resource_type'='project' THEN scanned:=scanned+1;END IF;\n    IF scanned>p_rows THEN RAISE EXCEPTION 'role apply scope census budget' USING ERRCODE='54000';END IF;\n    scope_key:=jsonb_build_array(carrier->>'resource_type',carrier->>'resource_id')::text;\n    scope_state:=scope_rollup->scope_key;\n    IF scope_state IS NULL THEN\n     scope_count:=scope_count+1;\n     IF scope_count>4096 THEN RAISE EXCEPTION 'role apply scope census bound' USING ERRCODE='54000';END IF;\n     scope_state:=jsonb_build_object('scope_kind',carrier->>'resource_type','scope_id',carrier->>'resource_id',\n      'never',false,'max_expiry',NULL,'bad_never',false,'bad_max_expiry',NULL);\n    END IF;\n    scope_valid:=coalesce(\n     carrier->>'resource_type' IN ('account','project') AND coalesce(carrier->>'resource_id','')<>''\n     AND (carrier->>'resource_id')!~'[:#*[:space:][:cntrl:]]'\n     AND jsonb_typeof(carrier->'target')='object'\n     AND (NOT (carrier->'target' ? 'allInScope') OR jsonb_typeof(carrier#>'{target,allInScope}')='boolean')\n     AND (NOT (carrier->'target' ? 'resources') OR carrier#>'{target,resources}'='[]'::jsonb)\n     AND ((nullif(new_role->>'project_id','') IS NOT NULL\n       AND carrier->>'resource_type'='project' AND carrier->>'resource_id'=new_role->>'project_id')\n      OR (nullif(new_role->>'project_id','') IS NULL AND nullif(new_role->>'account_id','') IS NOT NULL\n       AND ((carrier->>'resource_type'='account' AND carrier->>'resource_id'=new_role->>'account_id')\n        OR (carrier->>'resource_type'='project' AND carrier_source.project_account=new_role->>'account_id')))),false);\n    carrier_expiry:=(carrier->>'expires_at')::timestamptz;\n    IF carrier_expiry IS NULL THEN\n     scope_state:=scope_state||jsonb_build_object('never',true);\n     IF NOT scope_valid THEN scope_state:=scope_state||jsonb_build_object('bad_never',true);END IF;\n    ELSE\n     scope_state:=scope_state||jsonb_build_object('max_expiry',greatest(carrier_expiry,(scope_state->>'max_expiry')::timestamptz));\n     IF NOT scope_valid THEN scope_state:=scope_state||jsonb_build_object('bad_max_expiry',greatest(carrier_expiry,(scope_state->>'bad_max_expiry')::timestamptz));END IF;\n    END IF;\n    scope_rollup:=jsonb_set(scope_rollup,ARRAY[scope_key],scope_state,true);\n   END IF;\n   IF retier AND carrier->>'status'<>'REVOKED' THEN\n    SELECT coalesce(jsonb_agg(jsonb_build_object('user',t.fga_user,'relation',t.relation,'object',t.object)\n     ORDER BY t.object COLLATE \"C\",t.fga_user COLLATE \"C\",t.relation COLLATE \"C\"),'[]') INTO old_tuples\n", "   'origin',jsonb_build_object('family','role.create','role',new_role->>'id'),'row',row_value,'stamp','transaction'));\n END IF;\n IF NOT creation AND promote THEN\n  FOR carrier IN SELECT to_jsonb(b) FROM kaname.access_bindings b WHERE b.role_id=new_role->>'id' ORDER BY b.id COLLATE \"C\" LIMIT 100001 LOOP\n   carriers:=carriers+1;scanned:=scanned+1;\n   IF carriers>p_rows OR scanned>p_rows OR jsonb_array_length(maximum)>100000 THEN RAISE EXCEPTION 'role sequence population bound' USING ERRCODE='54000';END IF;\n   IF retier AND carrier->>'status'<>'REVOKED' THEN\n    SELECT coalesce(jsonb_agg(jsonb_build_object('user',t.fga_user,'relation',t.relation,'object',t.object)\n     ORDER BY t.object COLLATE \"C\",t.fga_user COLLATE \"C\",t.relation COLLATE \"C\"),'[]') INTO old_tuples\n"], ["  root_stamp:=greatest(root_stamp,(old_role->>'created_at')::timestamptz);\n  IF jsonb_array_length(mask)>0 THEN new_role:=new_role||jsonb_build_object('updated_at',root_stamp);END IF;\n END IF;\n -- Scope census нужен для новой explicit apply authoring, включая повторную\n -- отправку тех же rules. Metadata-only не включает этот lane.\n IF creation OR promote THEN\n  SELECT EXISTS(SELECT 1 FROM jsonb_array_elements(new_role->'rules') r\n   WHERE r->>'module'='iam' AND r->'resources' ? 'accessLabel' AND r->'verbs' ? 'apply')\n  INTO access_label_scope_needed;\n END IF;\n IF old_role IS DISTINCT FROM new_role THEN\n  ordinal:=ordinal+1;\n  origin:=jsonb_build_object('table','roles','operation',CASE WHEN creation THEN 'INSERT' ELSE 'UPDATE' END,\n", "  root_stamp:=greatest(root_stamp,(old_role->>'created_at')::timestamptz);\n  IF jsonb_array_length(mask)>0 THEN new_role:=new_role||jsonb_build_object('updated_at',root_stamp);END IF;\n END IF;\n IF old_role IS DISTINCT FROM new_role THEN\n  ordinal:=ordinal+1;\n  origin:=jsonb_build_object('table','roles','operation',CASE WHEN creation THEN 'INSERT' ELSE 'UPDATE' END,\n"], [" retier boolean;creation boolean;promote boolean;side_name text;event_type text;\n scanned integer:=1;reads integer:=1;carriers integer:=0;\n access_label_transition jsonb;access_label_frozen jsonb:='{}';access_label_needed boolean;\n access_label_scope_needed boolean:=false;scope_rollup jsonb:='{}';scope_count integer:=0;\n carrier_source record;scope_key text;scope_state jsonb;scope_valid boolean;\n carrier_expiry timestamptz;scope_ids jsonb;scope_values jsonb;fallback_scope jsonb;\n scope_maximum bigint;scope_cost bigint;\n access_label_authority_input jsonb;access_label_authority jsonb;\nBEGIN\n proof:=kaname.authority_protocol_attestation();\n", " retier boolean;creation boolean;promote boolean;side_name text;event_type text;\n scanned integer:=1;reads integer:=1;carriers integer:=0;\n access_label_transition jsonb;access_label_frozen jsonb:='{}';access_label_needed boolean;\n access_label_authority_input jsonb;access_label_authority jsonb;\nBEGIN\n proof:=kaname.authority_protocol_attestation();\n"]]$patch$::jsonb)
    ) AS changes(signature, before_sha, after_sha, substitutions) LOOP
        fn := pg_catalog.to_regprocedure('kaname.' || item.signature);
        IF fn IS NULL THEN RAISE EXCEPTION 'функция % для миграции отсутствует', item.signature USING ERRCODE='55000';END IF;
        SELECT p.prosrc INTO STRICT old_body FROM pg_catalog.pg_proc p WHERE p.oid=fn;
        IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(old_body,'UTF8')),'hex') IS DISTINCT FROM item.before_sha THEN
            RAISE EXCEPTION 'исходное тело функции % не соответствует этой миграции', item.signature USING ERRCODE='55000';
        END IF;
        new_body := old_body;
        FOR replacement IN SELECT value FROM pg_catalog.jsonb_array_elements(item.substitutions) LOOP
            needle := replacement->>0;
            IF length(new_body)-length(replace(new_body,needle,'')) IS DISTINCT FROM length(needle) THEN
                RAISE EXCEPTION 'фрагмент тела функции % не уникален', item.signature USING ERRCODE='55000';
            END IF;
            new_body := replace(new_body,needle,replacement->>1);
        END LOOP;
        IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(new_body,'UTF8')),'hex') IS DISTINCT FROM item.after_sha THEN
            RAISE EXCEPTION 'расчётное тело функции % изменилось', item.signature USING ERRCODE='55000';
        END IF;
        -- PostgreSQL восстанавливает сигнатуру и настройки, CREATE OR REPLACE
        -- сохраняет owner/ACL. Меняется ровно одно полное тело с известным SHA.
        definition := pg_catalog.pg_get_functiondef(fn);
        IF length(definition)-length(replace(definition,old_body,'')) IS DISTINCT FROM length(old_body) THEN
            RAISE EXCEPTION 'определение функции % не содержит единственного исходного тела', item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,old_body,new_body);
        IF (SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc,'UTF8')),'hex')
            FROM pg_catalog.pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.after_sha THEN
            RAISE EXCEPTION 'установленное тело функции % не совпадает с расчётным', item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
        RAISE EXCEPTION 'несогласованное состояние после подготовки обязательных проверок accessLabels' USING ERRCODE='55000';
    END IF;
END
$access_label_role_owner_census$;
-- +goose StatementEnd


DROP FUNCTION kaname.authority_access_label_role_required_questions_v1(jsonb,timestamptz);
