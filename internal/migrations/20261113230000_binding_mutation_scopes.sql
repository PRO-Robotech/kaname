-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- САНКЦИЯ: docs/engineering/acceptance/role-rights-stay-within-what-is-named.md,
-- редакция 4, ESC-32 (накат сохраняет ограничения); SHA-256
-- 3131d7ddfffa9b66857b94c70138b6ebfe7bdb77c7ca07f5333db88aefaae690.
-- Запись: docs/specs/reviews/role-rights-stay-within-what-is-named/3131d7ddfffa9b66857b94c70138b6ebfe7bdb77c7ca07f5333db88aefaae690.yaml;
-- событие: https://github.com/PRO-Robotech/kaname/issues/1034#issuecomment-6416087321.
-- Это основание сохраняющего ограничения rollout; не одобрение полной новой
-- grant-authority спецификации и не разрешение активировать public gates.
-- +goose Up
-- kaname#1034: typed binding OLD/NEW и настоящий canonical parent emitter.
-- Не разрешение операции; неизвестные формы по-прежнему требуют global.
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_binding_mutation_scopes(p_id text,p_new jsonb DEFAULT NULL)
RETURNS TABLE(accounts text[],global_scope boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE b jsonb; own text; role_owner text; role_system boolean; recipient record; typed record; seen integer:=0;
BEGIN
 accounts:=ARRAY[]::text[];global_scope:=true;
 IF p_id IS NULL OR p_id !~ '^[^:#*[:space:]]+$' THEN RETURN NEXT;RETURN;END IF;
 IF p_new IS NULL THEN SELECT pg_catalog.to_jsonb(x) INTO b FROM kaname.access_bindings x WHERE x.id=p_id;
 ELSE b:=p_new;END IF;
 IF b IS NULL OR b->>'id' IS DISTINCT FROM p_id THEN RETURN NEXT;RETURN;END IF;
 IF b->>'resource_type'='account' THEN SELECT id INTO own FROM kaname.accounts WHERE id=b->>'resource_id';
 ELSIF b->>'resource_type'='project' THEN SELECT p.account_id INTO own FROM kaname.projects p JOIN kaname.accounts a ON a.id=p.account_id WHERE p.id=b->>'resource_id';END IF;
 IF own IS NULL THEN RETURN NEXT;RETURN;END IF;
 accounts:=ARRAY[own];
 IF NOT EXISTS(SELECT 1 FROM kaname.roles r WHERE r.id=b->>'role_id') THEN RETURN NEXT;RETURN;END IF;
 SELECT kaname.authority_protocol_row_account('roles',pg_catalog.to_jsonb(r)),r.is_system INTO role_owner,role_system FROM kaname.roles r WHERE r.id=b->>'role_id';
 IF role_owner IS NULL THEN
  IF role_system IS DISTINCT FROM true THEN RETURN NEXT;RETURN;END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM kaname.accounts a WHERE a.id=role_owner) THEN RETURN NEXT;RETURN;END IF;
  accounts:=pg_catalog.array_append(accounts,role_owner);
 END IF;
 FOR recipient IN
  SELECT v.typ,v.id FROM (
   SELECT b->>'subject_type' AS typ,b->>'subject_id' AS id
   UNION SELECT s.subject_type,s.subject_id FROM kaname.access_binding_subjects s WHERE s.binding_id=p_id
  ) v LIMIT 34
 LOOP
  seen:=seen+1;IF seen>33 THEN RETURN NEXT;RETURN;END IF;
  SELECT * INTO STRICT typed FROM kaname.authority_group_object_subject(recipient.typ||':'||recipient.id||CASE WHEN recipient.typ='group' THEN '#member' ELSE '' END);
  IF typed.global_scope THEN RETURN NEXT;RETURN;END IF;
  IF typed.account_id<>'' THEN accounts:=pg_catalog.array_append(accounts,typed.account_id);END IF;
 END LOOP;
 SELECT pg_catalog.array_agg(DISTINCT x ORDER BY x) INTO accounts FROM pg_catalog.unnest(accounts) x;
 global_scope:=false;RETURN NEXT;
END $$;
-- +goose StatementEnd
-- kaname#1034: точная предыдущая реализация сохраняется под private helper.
-- CREATE OR REPLACE основного имени сохраняет OID для уже подготовленных callers.
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_protocol_row_scopes_before_binding(p_table text,p_row jsonb)
RETURNS TABLE(accounts text[],global_scope boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE payload jsonb;obj text;subject text;rels text[];ordered text[];g text;a text;s record;recipient record;
BEGIN
 accounts:=ARRAY[]::text[];global_scope:=true;
 IF p_table='groups' THEN
  SELECT id INTO a FROM kaname.accounts WHERE id=p_row->>'account_id';
  IF a IS NULL THEN RETURN NEXT;RETURN;END IF;
  SELECT * INTO STRICT s FROM kaname.authority_group_object_scopes(p_row->>'id',a);
  IF s.global_scope THEN RETURN NEXT;RETURN;END IF;
  SELECT pg_catalog.array_agg(DISTINCT x ORDER BY x) INTO accounts FROM pg_catalog.unnest(pg_catalog.array_append(s.accounts,a)) x;
  global_scope:=false;RETURN NEXT;RETURN;
 ELSIF p_table='fga_outbox' AND p_row->'payload'->>'object' LIKE 'iam_group:%' THEN
  payload:=p_row->'payload';obj:=payload->>'object';subject:=payload->>'user';
  IF p_row->>'event_type' IS NULL OR p_row->>'event_type' NOT IN ('fga.tuple.write','fga.tuple.delete')
   OR pg_catalog.jsonb_typeof(payload) IS DISTINCT FROM 'object'
   OR (payload-ARRAY['user','object','relation','relations'])<>'{}'::jsonb
   OR pg_catalog.jsonb_typeof(payload->'user') IS DISTINCT FROM 'string'
   OR pg_catalog.jsonb_typeof(payload->'object') IS DISTINCT FROM 'string' THEN RETURN NEXT;RETURN;END IF;
  IF payload ? 'relations' THEN
   IF pg_catalog.jsonb_typeof(payload->'relations') IS DISTINCT FROM 'array' THEN RETURN NEXT;RETURN;END IF;
   IF pg_catalog.jsonb_array_length(payload->'relations') NOT BETWEEN 2 AND 7
    OR EXISTS(SELECT 1 FROM pg_catalog.jsonb_array_elements(payload->'relations') v WHERE pg_catalog.jsonb_typeof(v) IS DISTINCT FROM 'string') THEN RETURN NEXT;RETURN;END IF;
   SELECT pg_catalog.array_agg(v ORDER BY n) INTO rels FROM pg_catalog.jsonb_array_elements_text(payload->'relations') WITH ORDINALITY t(v,n);
   SELECT pg_catalog.array_agg(DISTINCT v ORDER BY v) INTO ordered FROM pg_catalog.unnest(rels) v;
   IF rels IS DISTINCT FROM ordered THEN RETURN NEXT;RETURN;END IF;
   IF p_row->>'event_type'='fga.tuple.write' THEN
    IF payload->>'relation' IS DISTINCT FROM rels[1] THEN RETURN NEXT;RETURN;END IF;
   ELSIF payload ? 'relation' THEN RETURN NEXT;RETURN;END IF;
  ELSE
   IF pg_catalog.jsonb_typeof(payload->'relation') IS DISTINCT FROM 'string' THEN RETURN NEXT;RETURN;END IF;
   rels:=ARRAY[payload->>'relation'];
  END IF;
 ELSIF p_table='relation_fact' AND p_row->>'object_type'='iam_group' THEN
  IF p_row->>'condition_name' IS DISTINCT FROM '' OR p_row->'condition_params' IS DISTINCT FROM '{}'::jsonb THEN RETURN NEXT;RETURN;END IF;
  obj:='iam_group:'||(p_row->>'object_id');subject:=p_row->>'subject';rels:=ARRAY[p_row->>'relation'];
 ELSE
  RETURN QUERY SELECT x.accounts,x.global_scope FROM kaname.authority_group_member_row_scopes(p_table,p_row) x;RETURN;
 END IF;
 IF obj IS NULL OR obj !~ '^iam_group:[^:#*[:space:]]+$' THEN RETURN NEXT;RETURN;END IF;
 g:=pg_catalog.split_part(obj,':',2);
 IF rels=ARRAY['account']::text[] THEN
  SELECT gr.account_id INTO a FROM kaname.groups gr JOIN kaname.accounts ac ON ac.id=gr.account_id WHERE gr.id=g;
  IF a IS NOT NULL AND subject='account:'||a THEN accounts:=ARRAY[a];global_scope:=false;END IF;
  RETURN NEXT;RETURN;
 END IF;
 -- Закрытые direct arms фактического iam_group; derived admin-from-account
 -- или непонятный тип/condition никогда не превращаются в локальный scope.
 IF rels IS NULL OR NOT rels <@ ARRAY['admin','editor','viewer','v_get','v_list','v_update','v_delete']::text[] THEN RETURN NEXT;RETURN;END IF;
 SELECT * INTO STRICT s FROM kaname.authority_group_object_scopes(g);
 SELECT * INTO STRICT recipient FROM kaname.authority_group_object_subject(subject);
 IF s.global_scope OR recipient.global_scope THEN RETURN NEXT;RETURN;END IF;
 accounts:=s.accounts;
 IF recipient.account_id<>'' THEN accounts:=pg_catalog.array_append(accounts,recipient.account_id);END IF;
 SELECT pg_catalog.array_agg(DISTINCT x ORDER BY x) INTO accounts FROM pg_catalog.unnest(accounts) x;
 global_scope:=false;RETURN NEXT;
END $$;
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
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_row_scopes(p_table text,p_row jsonb)
RETURNS TABLE(accounts text[],global_scope boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE payload jsonb;obj text;subject text;rels text[];ordered text[];g text;a text;s record;recipient record;
BEGIN
 accounts:=ARRAY[]::text[];global_scope:=true;
 IF p_table='groups' THEN
  SELECT id INTO a FROM kaname.accounts WHERE id=p_row->>'account_id';
  IF a IS NULL THEN RETURN NEXT;RETURN;END IF;
  SELECT * INTO STRICT s FROM kaname.authority_group_object_scopes(p_row->>'id',a);
  IF s.global_scope THEN RETURN NEXT;RETURN;END IF;
  SELECT pg_catalog.array_agg(DISTINCT x ORDER BY x) INTO accounts FROM pg_catalog.unnest(pg_catalog.array_append(s.accounts,a)) x;
  global_scope:=false;RETURN NEXT;RETURN;
 ELSIF p_table='fga_outbox' AND p_row->'payload'->>'object' LIKE 'iam_group:%' THEN
  payload:=p_row->'payload';obj:=payload->>'object';subject:=payload->>'user';
  IF p_row->>'event_type' IS NULL OR p_row->>'event_type' NOT IN ('fga.tuple.write','fga.tuple.delete')
   OR pg_catalog.jsonb_typeof(payload) IS DISTINCT FROM 'object'
   OR (payload-ARRAY['user','object','relation','relations'])<>'{}'::jsonb
   OR pg_catalog.jsonb_typeof(payload->'user') IS DISTINCT FROM 'string'
   OR pg_catalog.jsonb_typeof(payload->'object') IS DISTINCT FROM 'string' THEN RETURN NEXT;RETURN;END IF;
  IF payload ? 'relations' THEN
   IF pg_catalog.jsonb_typeof(payload->'relations') IS DISTINCT FROM 'array' THEN RETURN NEXT;RETURN;END IF;
   IF pg_catalog.jsonb_array_length(payload->'relations') NOT BETWEEN 2 AND 7
    OR EXISTS(SELECT 1 FROM pg_catalog.jsonb_array_elements(payload->'relations') v WHERE pg_catalog.jsonb_typeof(v) IS DISTINCT FROM 'string') THEN RETURN NEXT;RETURN;END IF;
   SELECT pg_catalog.array_agg(v ORDER BY n) INTO rels FROM pg_catalog.jsonb_array_elements_text(payload->'relations') WITH ORDINALITY t(v,n);
   SELECT pg_catalog.array_agg(DISTINCT v ORDER BY v) INTO ordered FROM pg_catalog.unnest(rels) v;
   IF rels IS DISTINCT FROM ordered THEN RETURN NEXT;RETURN;END IF;
   IF p_row->>'event_type'='fga.tuple.write' THEN
    IF payload->>'relation' IS DISTINCT FROM rels[1] THEN RETURN NEXT;RETURN;END IF;
   ELSIF payload ? 'relation' THEN RETURN NEXT;RETURN;END IF;
  ELSE
   IF pg_catalog.jsonb_typeof(payload->'relation') IS DISTINCT FROM 'string' THEN RETURN NEXT;RETURN;END IF;
   rels:=ARRAY[payload->>'relation'];
  END IF;
 ELSIF p_table='relation_fact' AND p_row->>'object_type'='iam_group' THEN
  IF p_row->>'condition_name' IS DISTINCT FROM '' OR p_row->'condition_params' IS DISTINCT FROM '{}'::jsonb THEN RETURN NEXT;RETURN;END IF;
  obj:='iam_group:'||(p_row->>'object_id');subject:=p_row->>'subject';rels:=ARRAY[p_row->>'relation'];
 ELSE
  RETURN QUERY SELECT x.accounts,x.global_scope FROM kaname.authority_group_member_row_scopes(p_table,p_row) x;RETURN;
 END IF;
 IF obj IS NULL OR obj !~ '^iam_group:[^:#*[:space:]]+$' THEN RETURN NEXT;RETURN;END IF;
 g:=pg_catalog.split_part(obj,':',2);
 IF rels=ARRAY['account']::text[] THEN
  SELECT gr.account_id INTO a FROM kaname.groups gr JOIN kaname.accounts ac ON ac.id=gr.account_id WHERE gr.id=g;
  IF a IS NOT NULL AND subject='account:'||a THEN accounts:=ARRAY[a];global_scope:=false;END IF;
  RETURN NEXT;RETURN;
 END IF;
 -- Закрытые direct arms фактического iam_group; derived admin-from-account
 -- или непонятный тип/condition никогда не превращаются в локальный scope.
 IF rels IS NULL OR NOT rels <@ ARRAY['admin','editor','viewer','v_get','v_list','v_update','v_delete']::text[] THEN RETURN NEXT;RETURN;END IF;
 SELECT * INTO STRICT s FROM kaname.authority_group_object_scopes(g);
 SELECT * INTO STRICT recipient FROM kaname.authority_group_object_subject(subject);
 IF s.global_scope OR recipient.global_scope THEN RETURN NEXT;RETURN;END IF;
 accounts:=s.accounts;
 IF recipient.account_id<>'' THEN accounts:=pg_catalog.array_append(accounts,recipient.account_id);END IF;
 SELECT pg_catalog.array_agg(DISTINCT x ORDER BY x) INTO accounts FROM pg_catalog.unnest(accounts) x;
 global_scope:=false;RETURN NEXT;
END $$;
-- +goose StatementEnd
DROP FUNCTION kaname.authority_protocol_row_scopes_before_binding(text,jsonb);
DROP FUNCTION kaname.authority_binding_mutation_scopes(text,jsonb);
