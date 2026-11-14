-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Приёмка: docs/engineering/acceptance/role-rights-stay-within-what-is-named.md
-- ESC-32/Р4: сохранение ограничений; 3131d7ddfffa9b66857b94c70138b6ebfe7bdb77c7ca07f5333db88aefaae690.
-- kaname#1034: actual Role.Create пишет канонический account parent в той же TX.
-- Классификация замыкает обе стороны на настоящем владельце, не выдаёт права UC.
-- Не включает public gates и не одобряет весь новый grant-authority контракт.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_row_scopes(p_table text,p_row jsonb)
RETURNS TABLE(accounts text[],global_scope boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE bid text; payload jsonb; obj text; rel text; subject text; b record; s record; typed record; extra record; role_key text; role_account text;
BEGIN
 accounts:=ARRAY[]::text[];global_scope:=true;
 IF (p_table='fga_outbox' AND p_row->'payload'->>'object' LIKE 'iam_role:%')
 OR (p_table='relation_fact' AND p_row->>'object_type'='iam_role') THEN
  IF p_table='fga_outbox' THEN
   payload:=p_row->'payload';
   IF p_row->>'event_type' IS NULL OR p_row->>'event_type' NOT IN ('fga.tuple.write','fga.tuple.delete')
    OR pg_catalog.jsonb_typeof(payload) IS DISTINCT FROM 'object'
    OR (payload-ARRAY['user','relation','object'])<>'{}'::jsonb
    OR pg_catalog.jsonb_typeof(payload->'user') IS DISTINCT FROM 'string'
    OR pg_catalog.jsonb_typeof(payload->'relation') IS DISTINCT FROM 'string'
    OR pg_catalog.jsonb_typeof(payload->'object') IS DISTINCT FROM 'string' THEN RETURN NEXT;RETURN;END IF;
   obj:=payload->>'object';rel:=payload->>'relation';subject:=payload->>'user';
  ELSE
   IF p_row->>'condition_name' IS DISTINCT FROM '' OR p_row->'condition_params' IS DISTINCT FROM '{}'::jsonb
    OR pg_catalog.jsonb_typeof(p_row->'object_id') IS DISTINCT FROM 'string'
    OR pg_catalog.jsonb_typeof(p_row->'relation') IS DISTINCT FROM 'string'
    OR pg_catalog.jsonb_typeof(p_row->'subject') IS DISTINCT FROM 'string' THEN RETURN NEXT;RETURN;END IF;
   obj:='iam_role:'||(p_row->>'object_id');rel:=p_row->>'relation';subject:=p_row->>'subject';
  END IF;
  -- Связь участвует в derived super_admin: обе стороны выводятся только из
  -- настоящей account-роли. Нельзя назначить произвольный чужой parent.
  IF obj IS NULL OR obj !~ '^iam_role:[^:#*[:space:]]+$' OR rel IS DISTINCT FROM 'account' THEN RETURN NEXT;RETURN;END IF;
  role_key:=pg_catalog.split_part(obj,':',2);
  SELECT r.account_id INTO role_account FROM kaname.roles r JOIN kaname.accounts a ON a.id=r.account_id
   WHERE r.id=role_key AND NOT r.is_system AND r.project_id IS NULL;
  IF role_account IS NOT NULL AND subject='account:'||role_account THEN
   accounts:=ARRAY[role_account];global_scope:=false;
  END IF;
  RETURN NEXT;RETURN;
 ELSIF p_table='access_bindings' THEN
  RETURN QUERY SELECT x.accounts,x.global_scope FROM kaname.authority_binding_mutation_scopes(p_row->>'id',p_row) x;RETURN;
 ELSIF p_table IN ('access_binding_subjects','access_binding_target_members','access_binding_emitted_tuples') THEN
  bid:=p_row->>'binding_id';
  SELECT * INTO STRICT s FROM kaname.authority_binding_mutation_scopes(bid);
  IF s.global_scope THEN RETURN NEXT;RETURN;END IF;
  accounts:=s.accounts;
  IF p_table='access_binding_subjects' THEN
   -- В BEFORE ROW новый subject ещё не лежит в дочерней таблице.
   SELECT * INTO STRICT typed FROM kaname.authority_group_object_subject((p_row->>'subject_type')||':'||(p_row->>'subject_id')||CASE WHEN p_row->>'subject_type'='group' THEN '#member' ELSE '' END);
   IF typed.global_scope THEN accounts:=ARRAY[]::text[];RETURN NEXT;RETURN;END IF;
   IF typed.account_id<>'' THEN accounts:=pg_catalog.array_append(accounts,typed.account_id);END IF;
  ELSIF p_table='access_binding_target_members' THEN
   IF p_row->>'object_type' IS DISTINCT FROM 'iam.group' THEN accounts:=ARRAY[]::text[];RETURN NEXT;RETURN;END IF;
   SELECT * INTO STRICT extra FROM kaname.authority_group_object_scopes(p_row->>'object_id');
   IF extra.global_scope THEN accounts:=ARRAY[]::text[];RETURN NEXT;RETURN;END IF;
   accounts:=accounts||extra.accounts;
  ELSIF p_table='access_binding_emitted_tuples' THEN
   -- Ledger должен нести тот же доказанный tuple, который увидит emitter.
   -- Неизвестный member/source object не приписывается аккаунту carrier.
   IF p_row->>'member_object_type'='iam.group' THEN
    SELECT * INTO STRICT extra FROM kaname.authority_group_object_scopes(p_row->>'member_object_id');
    IF extra.global_scope THEN accounts:=ARRAY[]::text[];RETURN NEXT;RETURN;END IF;
    accounts:=accounts||extra.accounts;
   ELSIF p_row->>'member_object_type' IS DISTINCT FROM '' OR p_row->>'member_object_id' IS DISTINCT FROM '' THEN
    accounts:=ARRAY[]::text[];RETURN NEXT;RETURN;
   END IF;
   SELECT * INTO STRICT extra FROM kaname.authority_protocol_row_scopes('fga_outbox',pg_catalog.jsonb_build_object(
    'event_type','fga.tuple.delete','payload',pg_catalog.jsonb_build_object('user',p_row->>'fga_user','relation',p_row->>'relation','object',p_row->>'object')));
   IF extra.global_scope THEN accounts:=ARRAY[]::text[];RETURN NEXT;RETURN;END IF;
   accounts:=accounts||extra.accounts;
  END IF;
  SELECT pg_catalog.array_agg(DISTINCT x ORDER BY x) INTO accounts FROM pg_catalog.unnest(accounts) x;
  global_scope:=false;RETURN NEXT;RETURN;
 ELSIF p_table='fga_outbox' AND p_row->'payload'->>'object' LIKE 'iam_access_binding:%' THEN
  payload:=p_row->'payload';obj:=payload->>'object';rel:=payload->>'relation';subject:=payload->>'user';
  IF p_row->>'event_type' IS NULL OR p_row->>'event_type' NOT IN ('fga.tuple.write','fga.tuple.delete')
   OR pg_catalog.jsonb_typeof(payload) IS DISTINCT FROM 'object'
   OR (payload-ARRAY['user','relation','object'])<>'{}'::jsonb
   OR pg_catalog.jsonb_typeof(payload->'user') IS DISTINCT FROM 'string'
   OR pg_catalog.jsonb_typeof(payload->'relation') IS DISTINCT FROM 'string'
   OR pg_catalog.jsonb_typeof(payload->'object') IS DISTINCT FROM 'string' THEN RETURN NEXT;RETURN;END IF;
 ELSIF p_table='relation_fact' AND p_row->>'object_type'='iam_access_binding' THEN
  IF p_row->>'condition_name' IS DISTINCT FROM '' OR p_row->'condition_params' IS DISTINCT FROM '{}'::jsonb THEN RETURN NEXT;RETURN;END IF;
  obj:='iam_access_binding:'||(p_row->>'object_id');rel:=p_row->>'relation';subject:=p_row->>'subject';
 ELSE
  RETURN QUERY SELECT x.accounts,x.global_scope FROM kaname.authority_protocol_row_scopes_before_binding(p_table,p_row) x;RETURN;
 END IF;
 -- Только реальная lineage edge данного carrier, не произвольная похожая
 -- строка/обычный viewer/admin fact. DELETE отсутствующего parent остаётся global.
 IF obj IS NULL OR obj !~ '^iam_access_binding:[^:#*[:space:]]+$' THEN RETURN NEXT;RETURN;END IF;
 bid:=pg_catalog.split_part(obj,':',2);
 SELECT x.resource_type,x.resource_id INTO b FROM kaname.access_bindings x WHERE x.id=bid;
 IF NOT FOUND OR rel IS DISTINCT FROM b.resource_type OR subject IS DISTINCT FROM b.resource_type||':'||b.resource_id THEN RETURN NEXT;RETURN;END IF;
 RETURN QUERY SELECT x.accounts,x.global_scope FROM kaname.authority_binding_mutation_scopes(bid) x;
END $$;
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_row_scopes(p_table text,p_row jsonb)
RETURNS TABLE(accounts text[],global_scope boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE bid text; payload jsonb; obj text; rel text; subject text; b record; s record; typed record; extra record;
BEGIN
 accounts:=ARRAY[]::text[];global_scope:=true;
 IF p_table='access_bindings' THEN
  RETURN QUERY SELECT x.accounts,x.global_scope FROM kaname.authority_binding_mutation_scopes(p_row->>'id',p_row) x;RETURN;
 ELSIF p_table IN ('access_binding_subjects','access_binding_target_members','access_binding_emitted_tuples') THEN
  bid:=p_row->>'binding_id';
  SELECT * INTO STRICT s FROM kaname.authority_binding_mutation_scopes(bid);
  IF s.global_scope THEN RETURN NEXT;RETURN;END IF;
  accounts:=s.accounts;
  IF p_table='access_binding_subjects' THEN
   -- В BEFORE ROW новый subject ещё не лежит в дочерней таблице.
   SELECT * INTO STRICT typed FROM kaname.authority_group_object_subject((p_row->>'subject_type')||':'||(p_row->>'subject_id')||CASE WHEN p_row->>'subject_type'='group' THEN '#member' ELSE '' END);
   IF typed.global_scope THEN accounts:=ARRAY[]::text[];RETURN NEXT;RETURN;END IF;
   IF typed.account_id<>'' THEN accounts:=pg_catalog.array_append(accounts,typed.account_id);END IF;
  ELSIF p_table='access_binding_target_members' THEN
   IF p_row->>'object_type' IS DISTINCT FROM 'iam.group' THEN accounts:=ARRAY[]::text[];RETURN NEXT;RETURN;END IF;
   SELECT * INTO STRICT extra FROM kaname.authority_group_object_scopes(p_row->>'object_id');
   IF extra.global_scope THEN accounts:=ARRAY[]::text[];RETURN NEXT;RETURN;END IF;
   accounts:=accounts||extra.accounts;
  ELSIF p_table='access_binding_emitted_tuples' THEN
   -- Ledger должен нести тот же доказанный tuple, который увидит emitter.
   -- Неизвестный member/source object не приписывается аккаунту carrier.
   IF p_row->>'member_object_type'='iam.group' THEN
    SELECT * INTO STRICT extra FROM kaname.authority_group_object_scopes(p_row->>'member_object_id');
    IF extra.global_scope THEN accounts:=ARRAY[]::text[];RETURN NEXT;RETURN;END IF;
    accounts:=accounts||extra.accounts;
   ELSIF p_row->>'member_object_type' IS DISTINCT FROM '' OR p_row->>'member_object_id' IS DISTINCT FROM '' THEN
    accounts:=ARRAY[]::text[];RETURN NEXT;RETURN;
   END IF;
   SELECT * INTO STRICT extra FROM kaname.authority_protocol_row_scopes('fga_outbox',pg_catalog.jsonb_build_object(
    'event_type','fga.tuple.delete','payload',pg_catalog.jsonb_build_object('user',p_row->>'fga_user','relation',p_row->>'relation','object',p_row->>'object')));
   IF extra.global_scope THEN accounts:=ARRAY[]::text[];RETURN NEXT;RETURN;END IF;
   accounts:=accounts||extra.accounts;
  END IF;
  SELECT pg_catalog.array_agg(DISTINCT x ORDER BY x) INTO accounts FROM pg_catalog.unnest(accounts) x;
  global_scope:=false;RETURN NEXT;RETURN;
 ELSIF p_table='fga_outbox' AND p_row->'payload'->>'object' LIKE 'iam_access_binding:%' THEN
  payload:=p_row->'payload';obj:=payload->>'object';rel:=payload->>'relation';subject:=payload->>'user';
  IF p_row->>'event_type' IS NULL OR p_row->>'event_type' NOT IN ('fga.tuple.write','fga.tuple.delete')
   OR pg_catalog.jsonb_typeof(payload) IS DISTINCT FROM 'object'
   OR (payload-ARRAY['user','relation','object'])<>'{}'::jsonb
   OR pg_catalog.jsonb_typeof(payload->'user') IS DISTINCT FROM 'string'
   OR pg_catalog.jsonb_typeof(payload->'relation') IS DISTINCT FROM 'string'
   OR pg_catalog.jsonb_typeof(payload->'object') IS DISTINCT FROM 'string' THEN RETURN NEXT;RETURN;END IF;
 ELSIF p_table='relation_fact' AND p_row->>'object_type'='iam_access_binding' THEN
  IF p_row->>'condition_name' IS DISTINCT FROM '' OR p_row->'condition_params' IS DISTINCT FROM '{}'::jsonb THEN RETURN NEXT;RETURN;END IF;
  obj:='iam_access_binding:'||(p_row->>'object_id');rel:=p_row->>'relation';subject:=p_row->>'subject';
 ELSE
  RETURN QUERY SELECT x.accounts,x.global_scope FROM kaname.authority_protocol_row_scopes_before_binding(p_table,p_row) x;RETURN;
 END IF;
 -- Только реальная lineage edge данного carrier, не произвольная похожая
 -- строка/обычный viewer/admin fact. DELETE отсутствующего parent остаётся global.
 IF obj IS NULL OR obj !~ '^iam_access_binding:[^:#*[:space:]]+$' THEN RETURN NEXT;RETURN;END IF;
 bid:=pg_catalog.split_part(obj,':',2);
 SELECT x.resource_type,x.resource_id INTO b FROM kaname.access_bindings x WHERE x.id=bid;
 IF NOT FOUND OR rel IS DISTINCT FROM b.resource_type OR subject IS DISTINCT FROM b.resource_type||':'||b.resource_id THEN RETURN NEXT;RETURN;END IF;
 RETURN QUERY SELECT x.accounts,x.global_scope FROM kaname.authority_binding_mutation_scopes(bid) x;
END $$;
-- +goose StatementEnd
