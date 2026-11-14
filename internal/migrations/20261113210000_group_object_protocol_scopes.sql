-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- +goose Up
-- Приёмка: docs/engineering/acceptance/role-rights-stay-within-what-is-named.md
-- kaname#1034: защита полного действия выдачи и сохранение прежних строк при накате (ESC-32).
-- kaname#1034: только реальные iam.group object paths; strict не активируется.
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_group_object_subject(p_subject text)
RETURNS TABLE(account_id text,global_scope boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 account_id:=NULL;global_scope:=true;
 IF p_subject ~ '^user:[^:#*[:space:]]+$' THEN
  IF EXISTS(SELECT 1 FROM kaname.users WHERE id=pg_catalog.split_part(p_subject,':',2)) THEN account_id:='';global_scope:=false;END IF;
 ELSIF p_subject ~ '^service_account:[^:#*[:space:]]+$' THEN
  SELECT s.account_id INTO account_id FROM kaname.service_accounts s JOIN kaname.accounts a ON a.id=s.account_id WHERE s.id=pg_catalog.split_part(p_subject,':',2);
  global_scope:=account_id IS NULL;
 ELSIF p_subject ~ '^group:[^:#*[:space:]]+#member$' THEN
  SELECT g.account_id INTO account_id FROM kaname.groups g JOIN kaname.accounts a ON a.id=g.account_id WHERE g.id=pg_catalog.split_part(pg_catalog.split_part(p_subject,':',2),'#',1);
  global_scope:=account_id IS NULL;
 END IF;
 RETURN NEXT;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_group_object_scopes(p_group text,p_new_account text DEFAULT NULL)
RETURNS TABLE(accounts text[],global_scope boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE own text;previous_owner text;a text;b record;recipient record;typed record;seen integer:=0;
BEGIN
 accounts:=ARRAY[]::text[];global_scope:=true;
 IF p_group IS NULL OR p_group !~ '^[^:#*[:space:]]+$' THEN RETURN NEXT;RETURN;END IF;
 SELECT g.account_id INTO previous_owner FROM kaname.groups g JOIN kaname.accounts a ON a.id=g.account_id WHERE g.id=p_group;
 own:=previous_owner;
 -- NEW строка ещё не видна BEFORE ROW: её реальный anchor задаёт NEW.account_id.
 -- Тот же путь discovery используется Create ДО INSERT, включая новые names.
 IF p_new_account IS NOT NULL THEN SELECT id INTO own FROM kaname.accounts WHERE id=p_new_account;END IF;
 IF own IS NULL THEN RETURN NEXT;RETURN;END IF;
 accounts:=ARRAY[own];
 IF previous_owner IS NOT NULL THEN accounts:=pg_catalog.array_append(accounts,previous_owner);END IF;
 -- OLD ledger + все потенциальные NEW label matches. Метки намеренно не
 -- сужают discovery: UPDATE labels не требует расширять fence после locks.
 -- ACTIVE/PENDING включают истёкшие носители; им тоже нужен барьер от оживления.
 FOR b IN
  SELECT x.* FROM kaname.access_bindings x WHERE x.id IN (
   SELECT m.binding_id FROM kaname.access_binding_target_members m WHERE m.object_type='iam.group' AND m.object_id=p_group
   UNION SELECT e.binding_id FROM kaname.access_binding_emitted_tuples e WHERE (e.member_object_type='iam.group' AND e.member_object_id=p_group) OR e.object='iam_group:'||p_group
   UNION SELECT z.id FROM kaname.access_bindings z JOIN kaname.role_rule_selectors r ON r.role_id=z.role_id
    WHERE z.status IN ('ACTIVE','PENDING') AND r.object_types @> ARRAY['iam.group']::text[] AND
     (r.arm='labels' OR (r.arm='names' AND p_group=ANY(r.resource_names)) OR
      (r.arm='anchor' AND (z.resource_type NOT IN ('account','project') OR (z.resource_type='account' AND z.resource_id=own)))))
  ORDER BY x.id LIMIT 257
 LOOP
  seen:=seen+1;IF seen>256 THEN RETURN NEXT;RETURN;END IF;
  a:=NULL;
  IF b.resource_type='account' THEN SELECT id INTO a FROM kaname.accounts WHERE id=b.resource_id;
  ELSIF b.resource_type='project' THEN SELECT p.account_id INTO a FROM kaname.projects p JOIN kaname.accounts ac ON ac.id=p.account_id WHERE p.id=b.resource_id;END IF;
  IF a IS NULL THEN RETURN NEXT;RETURN;END IF;accounts:=pg_catalog.array_append(accounts,a);
  -- Типизированный owner роли — источник зависимости, не разрешение caller.
  IF NOT EXISTS(SELECT 1 FROM kaname.roles WHERE id=b.role_id) THEN RETURN NEXT;RETURN;END IF;
  SELECT kaname.authority_protocol_row_account('roles',pg_catalog.to_jsonb(r)) INTO a FROM kaname.roles r WHERE r.id=b.role_id;
  IF a IS NOT NULL THEN accounts:=pg_catalog.array_append(accounts,a);END IF;
  FOR recipient IN
   SELECT v.subject FROM (
    SELECT b.subject_type||':'||b.subject_id||CASE WHEN b.subject_type='group' THEN '#member' ELSE '' END AS subject
    UNION ALL SELECT s.subject_type||':'||s.subject_id||CASE WHEN s.subject_type='group' THEN '#member' ELSE '' END FROM kaname.access_binding_subjects s WHERE s.binding_id=b.id
    UNION ALL SELECT e.fga_user FROM kaname.access_binding_emitted_tuples e WHERE e.binding_id=b.id AND ((e.member_object_type='iam.group' AND e.member_object_id=p_group) OR e.object='iam_group:'||p_group)
   ) v LIMIT 257
  LOOP
   seen:=seen+1;IF seen>256 THEN RETURN NEXT;RETURN;END IF;
   SELECT * INTO STRICT typed FROM kaname.authority_group_object_subject(recipient.subject);
   IF typed.global_scope THEN RETURN NEXT;RETURN;END IF;
   IF typed.account_id<>'' THEN accounts:=pg_catalog.array_append(accounts,typed.account_id);END IF;
  END LOOP;
 END LOOP;
 SELECT pg_catalog.array_agg(DISTINCT x ORDER BY x) INTO accounts FROM pg_catalog.unnest(accounts) x;
 IF pg_catalog.cardinality(accounts)>255 THEN RETURN NEXT;RETURN;END IF;
 global_scope:=false;RETURN NEXT;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_group_member_row_scopes(p_table text,p_row jsonb)
RETURNS TABLE(accounts text[],global_scope boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE g text; typ text; member text; subject text; obj text; payload jsonb; a text;
BEGIN
 accounts:=ARRAY[]::text[]; global_scope:=true;
 IF p_table='group_members' THEN
  RETURN QUERY SELECT s.accounts,s.global_scope FROM kaname.authority_group_member_scopes(p_row->>'group_id',p_row->>'member_type',p_row->>'member_id') s; RETURN;
 ELSIF p_table='fga_outbox' THEN
  payload:=p_row->'payload';
  -- Реальный EmitWriteTx/EmitDeleteTx сохраняет одиночный tuple именно так.
  -- Множественные relations, conditions и посторонние поля здесь не угадываются.
  IF p_row->>'event_type' IS NULL OR p_row->>'event_type' NOT IN ('fga.tuple.write','fga.tuple.delete') OR pg_catalog.jsonb_typeof(payload) IS DISTINCT FROM 'object'
   OR (payload-ARRAY['user','relation','object'])<>'{}'::jsonb
   OR pg_catalog.jsonb_typeof(payload->'user') IS DISTINCT FROM 'string'
   OR pg_catalog.jsonb_typeof(payload->'object') IS DISTINCT FROM 'string'
   OR payload->>'relation' IS DISTINCT FROM 'member' THEN RETURN NEXT; RETURN; END IF;
  subject:=payload->>'user'; obj:=payload->>'object';
 ELSIF p_table='relation_fact' THEN
  IF p_row->>'object_type' IS DISTINCT FROM 'group' OR p_row->>'relation' IS DISTINCT FROM 'member'
   OR p_row->>'condition_name' IS DISTINCT FROM '' OR p_row->'condition_params' IS DISTINCT FROM '{}'::jsonb THEN RETURN NEXT; RETURN; END IF;
  obj:='group:'||(p_row->>'object_id'); subject:=p_row->>'subject';
 ELSE
  a:=kaname.authority_protocol_row_account(p_table,p_row);
  IF a IS NOT NULL THEN accounts:=ARRAY[a]; global_scope:=false; END IF;
  RETURN NEXT; RETURN;
 END IF;
 IF obj IS NULL OR subject IS NULL OR obj !~ '^group:[^:#*[:space:]]+$'
  OR subject !~ '^(user|service_account):[^:#*[:space:]]+$' THEN RETURN NEXT; RETURN; END IF;
 g:=pg_catalog.split_part(obj,':',2); typ:=pg_catalog.split_part(subject,':',1); member:=pg_catalog.split_part(subject,':',2);
 RETURN QUERY SELECT s.accounts,s.global_scope FROM kaname.authority_group_member_scopes(g,typ,member) s;
END $$;
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
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_row_scopes(p_table text,p_row jsonb)
RETURNS TABLE(accounts text[],global_scope boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE g text; typ text; member text; subject text; obj text; payload jsonb; a text;
BEGIN
 accounts:=ARRAY[]::text[]; global_scope:=true;
 IF p_table='group_members' THEN
  RETURN QUERY SELECT s.accounts,s.global_scope FROM kaname.authority_group_member_scopes(p_row->>'group_id',p_row->>'member_type',p_row->>'member_id') s; RETURN;
 ELSIF p_table='fga_outbox' THEN
  payload:=p_row->'payload';
  -- Реальный EmitWriteTx/EmitDeleteTx сохраняет одиночный tuple именно так.
  -- Множественные relations, conditions и посторонние поля здесь не угадываются.
  IF p_row->>'event_type' IS NULL OR p_row->>'event_type' NOT IN ('fga.tuple.write','fga.tuple.delete') OR pg_catalog.jsonb_typeof(payload) IS DISTINCT FROM 'object'
   OR (payload-ARRAY['user','relation','object'])<>'{}'::jsonb
   OR pg_catalog.jsonb_typeof(payload->'user') IS DISTINCT FROM 'string'
   OR pg_catalog.jsonb_typeof(payload->'object') IS DISTINCT FROM 'string'
   OR payload->>'relation' IS DISTINCT FROM 'member' THEN RETURN NEXT; RETURN; END IF;
  subject:=payload->>'user'; obj:=payload->>'object';
 ELSIF p_table='relation_fact' THEN
  IF p_row->>'object_type' IS DISTINCT FROM 'group' OR p_row->>'relation' IS DISTINCT FROM 'member'
   OR p_row->>'condition_name' IS DISTINCT FROM '' OR p_row->'condition_params' IS DISTINCT FROM '{}'::jsonb THEN RETURN NEXT; RETURN; END IF;
  obj:='group:'||(p_row->>'object_id'); subject:=p_row->>'subject';
 ELSE
  a:=kaname.authority_protocol_row_account(p_table,p_row);
  IF a IS NOT NULL THEN accounts:=ARRAY[a]; global_scope:=false; END IF;
  RETURN NEXT; RETURN;
 END IF;
 IF obj IS NULL OR subject IS NULL OR obj !~ '^group:[^:#*[:space:]]+$'
  OR subject !~ '^(user|service_account):[^:#*[:space:]]+$' THEN RETURN NEXT; RETURN; END IF;
 g:=pg_catalog.split_part(obj,':',2); typ:=pg_catalog.split_part(subject,':',1); member:=pg_catalog.split_part(subject,':',2);
 RETURN QUERY SELECT s.accounts,s.global_scope FROM kaname.authority_group_member_scopes(g,typ,member) s;
END $$;
-- +goose StatementEnd
DROP FUNCTION kaname.authority_group_member_row_scopes(text,jsonb);
DROP FUNCTION kaname.authority_group_object_scopes(text,text);
DROP FUNCTION kaname.authority_group_object_subject(text);
