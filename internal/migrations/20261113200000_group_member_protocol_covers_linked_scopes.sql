-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- kaname#1034: узкая классификация group#member; остальные факты требуют global.
-- Миграция не активирует protocol и не удостоверяет полноту adapters/D1/D2/D3.
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_group_member_scopes(p_group text,p_type text,p_member text)
RETURNS TABLE(accounts text[],global_scope boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a text; b record; seen integer:=0;
BEGIN
 accounts:=ARRAY[]::text[]; global_scope:=true;
 IF p_group IS NULL OR p_member IS NULL OR p_group !~ '^[^:#*[:space:]]+$' OR p_member !~ '^[^:#*[:space:]]+$' THEN RETURN NEXT; RETURN; END IF;
 SELECT g.account_id INTO a FROM kaname.groups g JOIN kaname.accounts x ON x.id=g.account_id WHERE g.id=p_group;
 IF a IS NULL THEN RETURN NEXT; RETURN; END IF;
 accounts:=pg_catalog.array_append(accounts,a);
 IF p_type='user' THEN
  IF NOT EXISTS(SELECT 1 FROM kaname.users WHERE id=p_member) THEN RETURN NEXT; RETURN; END IF;
 ELSIF p_type='service_account' THEN
  SELECT s.account_id INTO a FROM kaname.service_accounts s JOIN kaname.accounts x ON x.id=s.account_id WHERE s.id=p_member;
  IF a IS NULL THEN RETURN NEXT; RETURN; END IF;
  accounts:=pg_catalog.array_append(accounts,a);
 ELSE RETURN NEXT; RETURN;
 END IF;
 -- Физические носители, включая PENDING и истёкшие ACTIVE: никакого раннего
 -- исключения источника, которое позволило бы обойти барьер при оживлении.
 FOR b IN
  SELECT x.resource_type,x.resource_id FROM kaname.access_bindings x
  WHERE x.status IN ('ACTIVE','PENDING') AND
   ((x.subject_type='group' AND x.subject_id=p_group) OR EXISTS
    (SELECT 1 FROM kaname.access_binding_subjects s WHERE s.binding_id=x.id AND s.subject_type='group' AND s.subject_id=p_group))
  ORDER BY x.id LIMIT 257
 LOOP
  seen:=seen+1;
  IF seen>256 THEN RETURN NEXT; RETURN; END IF;
  a:=NULL;
  IF b.resource_type='account' THEN SELECT id INTO a FROM kaname.accounts WHERE id=b.resource_id;
  ELSIF b.resource_type='project' THEN
   SELECT pr.account_id INTO a FROM kaname.projects pr JOIN kaname.accounts ac ON ac.id=pr.account_id WHERE pr.id=b.resource_id;
  END IF;
  IF a IS NULL THEN RETURN NEXT; RETURN; END IF;
  accounts:=pg_catalog.array_append(accounts,a);
 END LOOP;
 SELECT pg_catalog.array_agg(DISTINCT x ORDER BY x) INTO accounts FROM pg_catalog.unnest(accounts) x;
 -- Один дополнительный ownership ref занимает сама группа.
 IF pg_catalog.cardinality(accounts)>255 THEN RETURN NEXT; RETURN; END IF;
 global_scope:=false; RETURN NEXT;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_protocol_row_scopes(p_table text,p_row jsonb)
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
CREATE OR REPLACE FUNCTION kaname.authority_protocol_row_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; scope record;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NOT NULL AND proof->>'mode'<>'global' THEN
  IF TG_OP<>'INSERT' THEN
   SELECT * INTO STRICT scope FROM kaname.authority_protocol_row_scopes(TG_TABLE_NAME,pg_catalog.to_jsonb(OLD));
   IF scope.global_scope OR pg_catalog.cardinality(scope.accounts)=0 OR NOT (proof->'accounts' ?& scope.accounts)
    THEN RAISE EXCEPTION 'authority OLD scope not covered' USING ERRCODE='42501'; END IF;
  END IF;
  IF TG_OP<>'DELETE' THEN
   SELECT * INTO STRICT scope FROM kaname.authority_protocol_row_scopes(TG_TABLE_NAME,pg_catalog.to_jsonb(NEW));
   IF scope.global_scope OR pg_catalog.cardinality(scope.accounts)=0 OR NOT (proof->'accounts' ?& scope.accounts)
    THEN RAISE EXCEPTION 'authority NEW scope not covered' USING ERRCODE='42501'; END IF;
  END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose Down
-- Перед возвратом консервативного guard уже начатые participants завершаются.
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_row_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; a text;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NOT NULL AND proof->>'mode'<>'global' THEN
  IF TG_OP<>'INSERT' THEN
   a:=kaname.authority_protocol_row_account(TG_TABLE_NAME,pg_catalog.to_jsonb(OLD));
   IF a IS NULL OR NOT (proof->'accounts' ? a) THEN RAISE EXCEPTION 'authority OLD scope not covered' USING ERRCODE='42501'; END IF;
  END IF;
  IF TG_OP<>'DELETE' THEN
   a:=kaname.authority_protocol_row_account(TG_TABLE_NAME,pg_catalog.to_jsonb(NEW));
   IF a IS NULL OR NOT (proof->'accounts' ? a) THEN RAISE EXCEPTION 'authority NEW scope not covered' USING ERRCODE='42501'; END IF;
  END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
DROP FUNCTION kaname.authority_protocol_row_scopes(text,jsonb);
DROP FUNCTION kaname.authority_group_member_scopes(text,text,text);
