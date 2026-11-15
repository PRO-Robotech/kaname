-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1034: семь закрытых команд Resource ABI, все ожидания до decision_at.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.membership_mirror_from_user() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- Первое появление человека: членство, названное колонкой строки,
        -- заводится здесь. Пустой аккаунт пропускается — строка без аккаунта
        -- законна, а членства без аккаунта не бывает.
        IF NEW.account_id IS NOT NULL AND NEW.account_id <> '' THEN
            INSERT INTO kaname.memberships (id, user_id, account_id, state, invited_by, created_at, updated_at)
            VALUES (kaname.membership_mirror_id(NEW.id, NEW.account_id),
                    NEW.id,
                    NEW.account_id,
                    CASE WHEN NEW.invite_status = 'PENDING' THEN 'PENDING' ELSE 'ACTIVE' END,
                    NEW.invited_by,
                    NEW.created_at,
                    now())
            ON CONFLICT (user_id, account_id) DO UPDATE
               SET state      = EXCLUDED.state,
                   invited_by = EXCLUDED.invited_by,
                   updated_at = now()
             WHERE kaname.memberships.state      IS DISTINCT FROM EXCLUDED.state
                OR kaname.memberships.invited_by IS DISTINCT FROM EXCLUDED.invited_by;
        END IF;
    ELSE
        -- Правка строки: зеркало ПРАВИТ существующее членство и НЕ заводит
        -- нового. Снятое членство не возвращается ничем, кроме приглашения.
        UPDATE kaname.memberships m
           SET state      = CASE WHEN NEW.invite_status = 'PENDING' THEN 'PENDING' ELSE 'ACTIVE' END,
               invited_by = NEW.invited_by,
               updated_at = now()
         WHERE m.user_id = NEW.id
           AND m.account_id = NEW.account_id
           AND (m.state      IS DISTINCT FROM CASE WHEN NEW.invite_status = 'PENDING' THEN 'PENDING' ELSE 'ACTIVE' END
             OR m.invited_by IS DISTINCT FROM NEW.invited_by);
    END IF;

    -- Активация относится к появлению неприглашённой личности или реальному
    -- выходу из PENDING. Правка дома/пригласившего и ACTIVE/BLOCKED не принимают
    -- новое решение о чужих членствах (own-account-and-identity, Р1).
    IF (TG_OP = 'INSERT' AND NEW.invite_status <> 'PENDING')
       OR (TG_OP = 'UPDATE' AND OLD.invite_status = 'PENDING' AND NEW.invite_status <> 'PENDING') THEN
        UPDATE kaname.memberships
           SET state = 'ACTIVE', updated_at = now()
         WHERE user_id = NEW.id AND state = 'PENDING';
    END IF;

    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_resource_before_write_v3(m jsonb,p_table text,p_op text,p_old jsonb,p_new jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE w jsonb; selected jsonb;
BEGIN
 p_old:=kaname._authority_resource_row_image_v2(p_table,p_old);
 p_new:=kaname._authority_resource_row_image_v2(p_table,p_new);
 -- users.expected_login_kind STORED вычисляется после BEFORE. Поле не
 -- исключается: BEFORE требует явный null; AFTER transition проверяет полный
 -- сохранённый образ через общий matcher и transition-проверку без нормализации.
 IF p_table='users' AND p_op='UPDATE' AND
  (NOT p_new ? 'expected_login_kind' OR p_new->'expected_login_kind' IS DISTINCT FROM 'null'::jsonb) THEN
  RAISE EXCEPTION 'unexpected users generated column BEFORE phase' USING ERRCODE='42501';
 END IF;
 FOR w IN SELECT value FROM jsonb_array_elements(m->'writes')
 WHERE value->>'table'=p_table AND value->>'operation'=p_op
 AND value->'old'=p_old
 AND (CASE WHEN p_table='users' AND p_op='UPDATE' THEN
  value->'new'||jsonb_build_object('expected_login_kind',NULL) ELSE value->'new' END)=p_new
 AND value->'command'=m->'object_command' LOOP
  PERFORM kaname._authority_resource_validate_write_v2(m,w);
  IF selected IS NOT NULL AND selected IS DISTINCT FROM w THEN
   RAISE EXCEPTION 'ambiguous resource producer write' USING ERRCODE='42501';
  END IF;
  selected:=w;
 END LOOP;
 IF selected IS NULL THEN RAISE EXCEPTION 'resource row absent from private manifest' USING ERRCODE='42501'; END IF;
 RETURN selected;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_resource_write_v2(m jsonb,p_table text,p_op text,p_old jsonb,p_new jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE w jsonb; selected jsonb;
BEGIN
 p_old:=kaname._authority_resource_row_image_v2(p_table,p_old);
 p_new:=kaname._authority_resource_row_image_v2(p_table,p_new);
 FOR w IN SELECT value FROM jsonb_array_elements(m->'writes')
 WHERE value->>'table'=p_table AND value->>'operation'=p_op
 AND value->'old'=p_old AND value->'new'=p_new
 AND value->'command'=m->'object_command' LOOP
  PERFORM kaname._authority_resource_validate_write_v2(m,w);
  IF selected IS NOT NULL AND selected IS DISTINCT FROM w THEN
   RAISE EXCEPTION 'ambiguous resource producer write' USING ERRCODE='42501';
  END IF;
  selected:=w;
 END LOOP;
 IF selected IS NULL THEN RAISE EXCEPTION 'resource row absent from private manifest' USING ERRCODE='42501'; END IF;
 RETURN selected;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_row_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; scope record; manifest jsonb; old_image jsonb; new_image jsonb; matched jsonb;
BEGIN
 IF TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' THEN
  RAISE EXCEPTION 'resource BEFORE guard context invalid' USING ERRCODE='42501';
 END IF;
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NOT NULL THEN
  IF TG_OP<>'INSERT' THEN old_image:=to_jsonb(OLD); END IF;
  IF TG_OP<>'DELETE' THEN new_image:=to_jsonb(NEW); END IF;
  matched:=kaname._authority_resource_before_write_v3(manifest,TG_TABLE_NAME,TG_OP,old_image,new_image);
  IF TG_TABLE_NAME='fga_outbox' AND TG_OP='INSERT' THEN
   PERFORM kaname._authority_resource_consume_outbox_v2(manifest,matched);
  END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
 END IF;
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


-- +goose StatementBegin
-- Снимок корневых строк — первый ограниченный слой общего capture.
-- Он не является полным effect graph и отдельно не разрешает body.
CREATE FUNCTION kaname._authority_crud_anchor_capture_v3(p_intent jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE descriptor jsonb;table_name text;target_id text;primary_row jsonb;primary_xmin text;primary_ctid text;
 parent_row jsonb;parent_xmin text;parent_ctid text;owner_row jsonb;owner_xmin text;owner_ctid text;account_id text;
 sources jsonb;owners jsonb:='[]'::jsonb;native_type text;native_id text;used_rows integer:=0;used_reads integer:=0;
BEGIN
 descriptor:=kaname._authority_crud_intent_v3(p_intent);
 IF p_rows IS NULL OR p_rows<1 OR p_rows>100000 OR p_reads IS NULL OR p_reads<1 OR p_reads>4096 THEN
  RAISE EXCEPTION 'CRUD anchor capture budget exceeded' USING ERRCODE='54000';END IF;
 table_name:=descriptor->>'table';target_id:=descriptor->>'id';
 -- Имя таблицы берётся только из закрытого descriptor, caller SQL отсутствует.
 IF table_name NOT IN ('accounts','projects','service_accounts','roles') THEN
  RAISE EXCEPTION 'invalid CRUD anchor table' USING ERRCODE='42501';END IF;
 EXECUTE format('SELECT to_jsonb(t),t.xmin::text,t.ctid::text FROM ONLY kaname.%I t WHERE t.id=$1',table_name)
 INTO primary_row,primary_xmin,primary_ctid USING target_id;
 used_reads:=1;
 IF primary_row IS NOT NULL THEN used_rows:=1;END IF;
 IF descriptor->>'command' LIKE '%.create' THEN account_id:=descriptor->>'account';
 ELSIF table_name='accounts' THEN account_id:=target_id;
 ELSE account_id:=primary_row->>'account_id';END IF;
 IF coalesce(account_id,'')<>'' AND table_name<>'accounts' THEN
  IF used_reads>=p_reads OR used_rows>=p_rows THEN
   RAISE EXCEPTION 'CRUD parent capture budget exceeded' USING ERRCODE='54000';END IF;
  SELECT to_jsonb(a),a.xmin::text,a.ctid::text INTO parent_row,parent_xmin,parent_ctid FROM ONLY kaname.accounts a WHERE a.id=account_id;
  used_reads:=used_reads+1;IF parent_row IS NOT NULL THEN used_rows:=used_rows+1;END IF;
 END IF;
 IF descriptor->>'command'='account.create' THEN
  IF used_reads>=p_reads OR used_rows>=p_rows THEN
   RAISE EXCEPTION 'CRUD owner capture budget exceeded' USING ERRCODE='54000';END IF;
  -- Users не содержит credential material; поля секрета живут в отдельных
  -- таблицах login_methods. Здесь сохраняется только FK owner anchor.
  SELECT jsonb_build_object('id',u.id),u.xmin::text,u.ctid::text INTO owner_row,owner_xmin,owner_ctid
  FROM ONLY kaname.users u WHERE u.id=p_intent#>>'{input,Account,OwnerUserID}';
  used_reads:=used_reads+1;IF owner_row IS NOT NULL THEN used_rows:=used_rows+1;END IF;
 END IF;
 IF descriptor->>'global'='false' THEN
  owners:=jsonb_build_array(jsonb_build_object('kind','account','id',account_id));
 ELSE
  IF descriptor->>'command' NOT LIKE '%.create' AND primary_row IS NOT NULL THEN
   owners:=jsonb_build_array(jsonb_build_object('kind',CASE table_name
    WHEN 'accounts' THEN 'account' WHEN 'projects' THEN 'project' WHEN 'service_accounts' THEN 'service_account' ELSE 'role' END,'id',target_id));
  ELSIF coalesce(account_id,'')<>'' THEN owners:=jsonb_build_array(jsonb_build_object('kind','account','id',account_id));END IF;
 END IF;
 native_type:=descriptor->>'model_type';native_id:=target_id;
 IF descriptor->>'command' IN ('project.create','service_account.create') THEN
  native_type:='account';native_id:=account_id;
 END IF;
 sources:=jsonb_build_object('descriptor',descriptor,'primary',jsonb_build_object('row',primary_row,'xmin',primary_xmin,'ctid',primary_ctid),
  'parent',jsonb_build_object('row',parent_row,'xmin',parent_xmin,'ctid',parent_ctid),'owner',jsonb_build_object('row',owner_row,'xmin',owner_xmin,'ctid',owner_ctid));
 RETURN jsonb_build_object('plan',jsonb_build_object('Mode',CASE WHEN descriptor->>'global'='true' THEN 2 ELSE 1 END,
   'Accounts',CASE WHEN descriptor->>'global'='true' THEN '[]'::jsonb ELSE jsonb_build_array(account_id) END),
  'owners',owners,'native_type',native_type,'native_id',native_id,'sources',sources,
  'logical_rows',used_rows,'logical_reads',used_reads);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Полный metadata graph изменяемых carriers. Чужой binding из role
-- cascade и secondary subject не исчезают из epoch/source footprint.
CREATE FUNCTION kaname._authority_crud_authority_graph_v3(p_intent jsonb,p_sources jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE descriptor jsonb;tables jsonb:='{}';rows_value jsonb;binding_ids text[];role_ids text[];project_ids text[];group_ids text[];
 used_rows integer:=0;used_reads integer:=0;entry record;selected_ids text[];query_text text;root_role text;
BEGIN
 descriptor:=kaname._authority_crud_intent_v3(p_intent);
 IF p_sources->'descriptor' IS DISTINCT FROM descriptor OR p_rows IS NULL OR p_rows<0 OR p_rows>100000
 OR p_reads IS NULL OR p_reads<0 OR p_reads>4096 THEN
  RAISE EXCEPTION 'invalid CRUD authority graph' USING ERRCODE='42501';END IF;
 SELECT coalesce(array_agg(DISTINCT id),ARRAY[]::text[]) INTO binding_ids FROM (
  SELECT value->>'id' id FROM jsonb_array_elements(p_sources->'scope_bindings')
  UNION SELECT value->'row'->>'binding_id' FROM jsonb_array_elements(coalesce(p_sources#>'{tables,access_binding_target_members}','[]'::jsonb))
 ) affected WHERE coalesce(id,'')<>'';
 root_role:=CASE WHEN descriptor->>'command'='account.create' THEN 'rol72122ce96bfec66e2'
  WHEN descriptor->>'command'='role.delete' THEN descriptor->>'id' END;
 -- Две первые выборки дают actual binding row + полный secondary population.
 FOR entry IN SELECT * FROM (VALUES ('access_bindings','id'),('access_binding_subjects','binding_id')) q(table_name,key_name) LOOP
  IF cardinality(binding_ids)=0 THEN tables:=tables||jsonb_build_object(entry.table_name,'[]'::jsonb);CONTINUE;END IF;
  IF used_reads>=p_reads THEN RAISE EXCEPTION 'CRUD carrier graph read budget exceeded' USING ERRCODE='54000';END IF;
  query_text:=format('SELECT coalesce(jsonb_agg(jsonb_build_object(''row'',row_value,''xmin'',xmin_value,''ctid'',ctid_value)
   ORDER BY row_value::text COLLATE "C"),''[]''::jsonb) FROM
   (SELECT to_jsonb(t) row_value,t.xmin::text xmin_value,t.ctid::text ctid_value FROM ONLY kaname.%I t
    WHERE t.%I=ANY($1) ORDER BY to_jsonb(t)::text COLLATE "C" LIMIT $2) captured',entry.table_name,entry.key_name);
  EXECUTE query_text INTO rows_value USING binding_ids,p_rows-used_rows+1;
  used_reads:=used_reads+1;used_rows:=used_rows+jsonb_array_length(rows_value);
  IF used_rows>p_rows THEN RAISE EXCEPTION 'CRUD carrier graph row budget exceeded' USING ERRCODE='54000';END IF;
  tables:=tables||jsonb_build_object(entry.table_name,rows_value);
 END LOOP;
 SELECT coalesce(array_agg(DISTINCT id),ARRAY[]::text[]) INTO role_ids FROM (
  SELECT root_role id
  UNION SELECT value->'row'->>'role_id' FROM jsonb_array_elements(tables->'access_bindings')
  UNION SELECT value->'row'->>'role_id' FROM jsonb_array_elements(coalesce(p_sources#>'{tables,role_bind_role_rule}','[]'::jsonb))
  UNION SELECT value->'row'->>'bound_role_id' FROM jsonb_array_elements(coalesce(p_sources#>'{tables,role_bind_role_rule}','[]'::jsonb))
 ) affected WHERE coalesce(id,'')<>'';
 FOR entry IN SELECT * FROM (VALUES ('roles','id'),('role_rule_selectors','role_id')) q(table_name,key_name) LOOP
  IF cardinality(role_ids)=0 THEN tables:=tables||jsonb_build_object(entry.table_name,'[]'::jsonb);CONTINUE;END IF;
  IF used_reads>=p_reads THEN RAISE EXCEPTION 'CRUD role graph read budget exceeded' USING ERRCODE='54000';END IF;
  query_text:=format('SELECT coalesce(jsonb_agg(jsonb_build_object(''row'',row_value,''xmin'',xmin_value,''ctid'',ctid_value)
   ORDER BY row_value::text COLLATE "C"),''[]''::jsonb) FROM
   (SELECT to_jsonb(t) row_value,t.xmin::text xmin_value,t.ctid::text ctid_value FROM ONLY kaname.%I t
    WHERE t.%I=ANY($1) ORDER BY to_jsonb(t)::text COLLATE "C" LIMIT $2) captured',entry.table_name,entry.key_name);
  EXECUTE query_text INTO rows_value USING role_ids,p_rows-used_rows+1;
  used_reads:=used_reads+1;used_rows:=used_rows+jsonb_array_length(rows_value);
  IF used_rows>p_rows THEN RAISE EXCEPTION 'CRUD role graph row budget exceeded' USING ERRCODE='54000';END IF;
  tables:=tables||jsonb_build_object(entry.table_name,rows_value);
 END LOOP;
 SELECT coalesce(array_agg(DISTINCT id),ARRAY[]::text[]) INTO project_ids FROM (
  SELECT value->'row'->>'project_id' id FROM jsonb_array_elements(tables->'roles')
  UNION SELECT value->'row'->>'resource_id' FROM jsonb_array_elements(tables->'access_bindings')
   WHERE value->'row'->>'resource_type'='project'
 ) affected WHERE coalesce(id,'')<>'';
 SELECT coalesce(array_agg(DISTINCT id),ARRAY[]::text[]) INTO group_ids FROM (
  SELECT value->'row'->>'object_id' id FROM jsonb_array_elements(coalesce(p_sources#>'{tables,access_binding_target_members}','[]'::jsonb))
   WHERE value->'row'->>'object_type'='iam.group'
  UNION SELECT value->'row'->>'member_object_id' FROM jsonb_array_elements(coalesce(p_sources#>'{tables,access_binding_emitted_tuples}','[]'::jsonb))
   WHERE value->'row'->>'member_object_type'='iam.group'
  UNION SELECT substr(value->'row'->>'object',11) FROM jsonb_array_elements(coalesce(p_sources#>'{tables,access_binding_emitted_tuples}','[]'::jsonb))
   WHERE value->'row'->>'object' LIKE 'iam_group:%'
 ) affected WHERE coalesce(id,'')<>'';
 FOR entry IN SELECT * FROM (VALUES ('projects',project_ids),('groups',group_ids)) q(table_name,ids) LOOP
  IF cardinality(entry.ids)=0 THEN tables:=tables||jsonb_build_object(entry.table_name,'[]'::jsonb);CONTINUE;END IF;
  IF used_reads>=p_reads THEN RAISE EXCEPTION 'CRUD owner graph read budget exceeded' USING ERRCODE='54000';END IF;
  query_text:=format('SELECT coalesce(jsonb_agg(jsonb_build_object(''row'',row_value,''xmin'',xmin_value,''ctid'',ctid_value)
   ORDER BY row_value::text COLLATE "C"),''[]''::jsonb) FROM
   (SELECT to_jsonb(t) row_value,t.xmin::text xmin_value,t.ctid::text ctid_value FROM ONLY kaname.%I t
    WHERE t.id=ANY($1) ORDER BY t.id COLLATE "C" LIMIT $2) captured',entry.table_name);
  EXECUTE query_text INTO rows_value USING entry.ids,p_rows-used_rows+1;
  used_reads:=used_reads+1;used_rows:=used_rows+jsonb_array_length(rows_value);
  IF used_rows>p_rows THEN RAISE EXCEPTION 'CRUD owner graph row budget exceeded' USING ERRCODE='54000';END IF;
  tables:=tables||jsonb_build_object(entry.table_name,rows_value);
 END LOOP;
 RETURN jsonb_build_object('tables',tables,'logical_rows',used_rows,'logical_reads',used_reads);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Конечные побочные строки семёрки: read-only capture не резервирует
-- ID и не изменяет счётчики. Отсутствующий ключ остаётся явным predicate.
CREATE FUNCTION kaname._authority_crud_aux_capture_v3(p_intent jsonb,p_sources jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE descriptor jsonb;command text;target_id text;owner_id text;owner_row jsonb;owner_xmin text;owner_ctid text;
 quota_carrier text;rate_carrier text;table_rows jsonb;tables jsonb:='{}';used_rows integer:=0;used_reads integer:=0;
 query_text text;entry record;limit_rows integer;
BEGIN
 descriptor:=kaname._authority_crud_intent_v3(p_intent);command:=descriptor->>'command';target_id:=descriptor->>'id';
 IF p_sources->'descriptor' IS DISTINCT FROM descriptor OR p_rows IS NULL OR p_rows<0 OR p_rows>100000
 OR p_reads IS NULL OR p_reads<0 OR p_reads>4096 THEN
  RAISE EXCEPTION 'invalid CRUD auxiliary capture' USING ERRCODE='42501';END IF;
 IF command NOT IN ('account.create','account.delete','service_account.create','service_account.delete') THEN
  RETURN jsonb_build_object('tables',tables,'logical_rows',0,'logical_reads',0);
 END IF;
 IF command IN ('account.create','account.delete') THEN
  owner_id:=CASE WHEN command='account.create' THEN p_intent#>>'{input,Account,OwnerUserID}'
   ELSE p_sources#>>'{primary,row,owner_user_id}' END;
  IF p_reads<1 THEN RAISE EXCEPTION 'CRUD quota owner read budget exceeded' USING ERRCODE='54000';END IF;
  SELECT jsonb_build_object('id',u.id,'external_id',u.external_id,'admission_carrier',u.admission_carrier),u.xmin::text,u.ctid::text
  INTO owner_row,owner_xmin,owner_ctid FROM ONLY kaname.users u WHERE u.id=owner_id;
  used_reads:=1;IF owner_row IS NOT NULL THEN used_rows:=1;END IF;
  IF used_rows>p_rows THEN RAISE EXCEPTION 'CRUD quota owner row budget exceeded' USING ERRCODE='54000';END IF;
  quota_carrier:=nullif(owner_row->>'external_id','');
  rate_carrier:=CASE WHEN quota_carrier LIKE 'own:%' THEN nullif(owner_row->>'admission_carrier','') ELSE quota_carrier END;
 ELSE quota_carrier:=target_id;END IF;
 -- Предикаты задаёт закрытая ветвь команды; вызывающий не задаёт SQL.
 FOR entry IN SELECT * FROM (VALUES
  ('issued_account_ids',command='account.create','t.id=$1',target_id,NULL::text,NULL::text),
  ('own_ceilings',command IN ('account.create','service_account.create'),'t.kind=$1',
   CASE WHEN command='account.create' THEN 'iam.account' ELSE 'iam.serviceAccount.credential' END,NULL::text,NULL::text),
  ('account_admission_rate_limits',command='account.create','t.kind=$1','iam.account',NULL::text,NULL::text),
  ('project_resource_quotas',quota_carrier IS NOT NULL,'t.carrier_type=$1 AND t.carrier_id=$2 AND t.kind=$3',
   CASE WHEN command LIKE 'account.%' THEN 'identity' ELSE 'iam.serviceAccount' END,quota_carrier,
   CASE WHEN command LIKE 'account.%' THEN 'iam.account' ELSE 'iam.serviceAccount.credential' END),
  ('identity_admission_windows',command='account.create' AND rate_carrier IS NOT NULL,'t.carrier_id=$1 AND t.kind=$2',
   rate_carrier,'iam.account',NULL::text)
 ) AS selected(table_name,needed,predicate,a,b,c) WHERE needed LOOP
  IF used_reads>=p_reads THEN RAISE EXCEPTION 'CRUD auxiliary read budget exceeded' USING ERRCODE='54000';END IF;
  limit_rows:=p_rows-used_rows+1;
  query_text:=format('SELECT coalesce(jsonb_agg(jsonb_build_object(''row'',row_value,''xmin'',xmin_value,''ctid'',ctid_value)
   ORDER BY row_value::text COLLATE "C"),''[]''::jsonb) FROM
   (SELECT to_jsonb(t) row_value,t.xmin::text xmin_value,t.ctid::text ctid_value FROM ONLY kaname.%I t
    WHERE %s ORDER BY to_jsonb(t)::text COLLATE "C" LIMIT $4) captured',entry.table_name,entry.predicate);
  EXECUTE query_text INTO table_rows USING entry.a,entry.b,entry.c,limit_rows;
  used_reads:=used_reads+1;used_rows:=used_rows+jsonb_array_length(table_rows);
  IF used_rows>p_rows THEN RAISE EXCEPTION 'CRUD auxiliary row budget exceeded' USING ERRCODE='54000';END IF;
  tables:=tables||jsonb_build_object(entry.table_name,table_rows);
 END LOOP;
 RETURN jsonb_build_object('tables',tables,'quota_owner',jsonb_build_object('row',owner_row,'xmin',owner_xmin,'ctid',owner_ctid),
  'quota_carrier',quota_carrier,'rate_carrier',rate_carrier,'logical_rows',used_rows,'logical_reads',used_reads);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Дополнительные таблицы не становятся authority source по названию.
-- В CRUD body разрешена только точная заранее скомпилированная строка;
-- raw/compat producer сохраняет прежний доступ и общий key-order backstop.
CREATE FUNCTION kaname._authority_crud_aux_write_v3() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;old_row jsonb;new_row jsonb;matched jsonb;ordinal integer;consumed jsonb;
BEGIN
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME NOT IN ('issued_account_ids','project_resource_quotas',
  'identity_admission_windows','role_grant_orphan','role_selector_prune')
 OR TG_LEVEL<>'ROW' OR TG_WHEN NOT IN ('BEFORE','AFTER') OR TG_OP NOT IN ('INSERT','UPDATE','DELETE') THEN
  RAISE EXCEPTION 'invalid CRUD auxiliary trigger context' USING ERRCODE='42501';END IF;
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NULL OR manifest->'intent'->>'kind' IS DISTINCT FROM 'crud' THEN
  IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
 END IF;
 IF TG_OP<>'INSERT' THEN old_row:=to_jsonb(OLD);END IF;
 IF TG_OP<>'DELETE' THEN new_row:=to_jsonb(NEW);END IF;
 consumed:=manifest#>'{registration_body,consumed_aux}';
 IF manifest->>'registration_program_claimed' IS DISTINCT FROM 'true'
 OR jsonb_typeof(consumed) IS DISTINCT FROM 'array'
 OR jsonb_typeof(manifest#>'{registration_physical,aux}') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'CRUD auxiliary program unavailable' USING ERRCODE='42501';END IF;
 SELECT value,position::integer INTO matched,ordinal
 FROM jsonb_array_elements(manifest#>'{registration_physical,aux}') WITH ORDINALITY e(value,position)
 WHERE value->'command'=manifest->'object_command' AND value->>'table'=TG_TABLE_NAME
  AND value->>'operation'=TG_OP AND value->'old'=coalesce(old_row,'null'::jsonb)
  AND value->'new'=coalesce(new_row,'null'::jsonb)
  AND NOT consumed @> jsonb_build_array(position)
 ORDER BY position LIMIT 1;
 IF ordinal IS NULL THEN RAISE EXCEPTION 'CRUD auxiliary row outside prepared command' USING ERRCODE='42501';END IF;
 IF TG_WHEN='AFTER' THEN
  IF matched->>'required' IS DISTINCT FROM 'true' THEN
   RAISE EXCEPTION 'CRUD attempted-only auxiliary image persisted' USING ERRCODE='42501';END IF;
  UPDATE pg_temp.kaname_authority_resource_manifest
  SET registration_body=jsonb_set(registration_body,'{consumed_aux}',consumed||jsonb_build_array(ordinal));
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Точные quota/rate/issued-ID images сохраняют существующие INSERT/UPSERT
-- ветви, including unconditional first admission. Отказный body сам вызывает
-- исходный quota/rate_refuse; compiler не заменяет их новым текстом ошибки.
CREATE FUNCTION kaname._authority_crud_aux_images_v3(p_intent jsonb,p_sources jsonb,p_program jsonb,p_tx_at timestamptz)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE descriptor jsonb;command text;command_no integer;images jsonb:='[]';old_row jsonb;new_row jsonb;attempt jsonb;
 ceiling jsonb;rate_limit jsonb;carrier text;kind text;carrier_type text;account_id text;window_reset boolean;
BEGIN
 descriptor:=kaname._authority_crud_intent_v3(p_intent);command:=descriptor->>'command';
 IF p_tx_at IS NULL OR p_sources->'descriptor' IS DISTINCT FROM descriptor
 OR p_program IS DISTINCT FROM kaname._authority_crud_command_plan_v3(p_intent,p_sources) THEN
  RAISE EXCEPTION 'CRUD auxiliary program not server derived' USING ERRCODE='42501';END IF;
 IF command NOT IN ('account.create','account.delete','service_account.create','service_account.delete') THEN RETURN images;END IF;
 SELECT ordinal::integer INTO STRICT command_no FROM jsonb_array_elements(p_program->'commands') WITH ORDINALITY c(value,ordinal)
 WHERE value->>'kind'=replace(command,'.create','.insert');
 IF command='account.create' AND kaname.account_id_has_generator_form(descriptor->>'id') THEN
  images:=images||kaname._authority_crud_image_v3(command_no,'issued_account_ids','INSERT',NULL,jsonb_build_object('id',descriptor->>'id'));
 END IF;
 carrier:=p_sources->>'quota_carrier';
 carrier_type:=CASE WHEN command LIKE 'account.%' THEN 'identity' ELSE 'iam.serviceAccount' END;
 kind:=CASE WHEN command LIKE 'account.%' THEN 'iam.account' ELSE 'iam.serviceAccount.credential' END;
 account_id:=CASE WHEN carrier_type='identity' THEN '' ELSE descriptor->>'account' END;
 IF coalesce(carrier,'')<>'' THEN
  SELECT value->'row' INTO old_row FROM jsonb_array_elements(coalesce(p_sources#>'{tables,project_resource_quotas}','[]'::jsonb));
  IF command='service_account.delete' THEN
   IF old_row IS NOT NULL THEN images:=images||kaname._authority_crud_image_v3(command_no,'project_resource_quotas','DELETE',old_row,NULL);END IF;
  ELSIF command='account.delete' THEN
   IF old_row IS NOT NULL THEN
    new_row:=old_row||jsonb_build_object('used',greatest((old_row->>'used')::bigint-1,0),'updated_at',p_tx_at);
    images:=images||kaname._authority_crud_image_v3(command_no,'project_resource_quotas','UPDATE',old_row,new_row);
   END IF;
  ELSE
   SELECT value->'row' INTO ceiling FROM jsonb_array_elements(coalesce(p_sources#>'{tables,own_ceilings}','[]'::jsonb))
    WHERE value->'row'->>'kind'=kind;
   IF ceiling IS NULL THEN
    -- Account quota refusal удаляет текущий снимок перед исключением;
    -- транзакция откатится целиком. Lifecycle SA при отсутствии ceiling
    -- просто не вставляет строку, ровно как исходный INSERT SELECT.
    IF command='account.create' AND old_row IS NOT NULL THEN
     images:=images||kaname._authority_crud_image_v3(command_no,'project_resource_quotas','DELETE',old_row,NULL);
    END IF;
   ELSE
    attempt:=jsonb_build_object('carrier_type',carrier_type,'carrier_id',carrier,'kind',kind,'used',0,
     'limit_value',ceiling->'limit_value','source_scope','DEFAULT','source_scope_id','','limit_revision',0,
     'synced_at',p_tx_at,'account_id',account_id,'created_at',p_tx_at,'updated_at',p_tx_at);
    images:=images||kaname._authority_crud_image_v3(command_no,'project_resource_quotas','INSERT',NULL,attempt,old_row IS NULL);
    IF command='account.create' THEN
     old_row:=coalesce(old_row,attempt);
     new_row:=old_row||jsonb_build_object('limit_value',ceiling->'limit_value','source_scope','DEFAULT',
      'source_scope_id','','limit_revision',0,'synced_at',p_tx_at,'updated_at',p_tx_at);
     images:=images||kaname._authority_crud_image_v3(command_no,'project_resource_quotas','UPDATE',old_row,new_row);
     old_row:=new_row;
     IF (old_row->>'used')::bigint<(old_row->>'limit_value')::bigint THEN
      new_row:=old_row||jsonb_build_object('used',(old_row->>'used')::bigint+1,'updated_at',p_tx_at);
      images:=images||kaname._authority_crud_image_v3(command_no,'project_resource_quotas','UPDATE',old_row,new_row);
     END IF;
    END IF;
   END IF;
  END IF;
 END IF;
 IF command='account.create' AND coalesce(p_sources->>'rate_carrier','')<>'' THEN
  SELECT value->'row' INTO rate_limit FROM jsonb_array_elements(coalesce(p_sources#>'{tables,account_admission_rate_limits}','[]'::jsonb))
   WHERE value->'row'->>'kind'='iam.account' AND value->'row'->>'withdrawn_at' IS NULL;
  IF rate_limit IS NOT NULL THEN
   SELECT value->'row' INTO old_row FROM jsonb_array_elements(coalesce(p_sources#>'{tables,identity_admission_windows}','[]'::jsonb));
   attempt:=jsonb_build_object('carrier_id',p_sources->>'rate_carrier','kind','iam.account','window_started_at',p_tx_at,
    'admitted',1,'updated_at',p_tx_at);
   images:=images||kaname._authority_crud_image_v3(command_no,'identity_admission_windows','INSERT',NULL,attempt,old_row IS NULL);
   IF old_row IS NOT NULL THEN
    window_reset:=p_tx_at>=(old_row->>'window_started_at')::timestamptz+make_interval(secs=>(rate_limit->>'window_seconds')::double precision);
    IF (CASE WHEN window_reset THEN 1 ELSE (old_row->>'admitted')::bigint+1 END)<=(rate_limit->>'max_events')::bigint THEN
     new_row:=old_row||jsonb_build_object('window_started_at',CASE WHEN window_reset THEN to_jsonb(p_tx_at) ELSE old_row->'window_started_at' END,
      'admitted',CASE WHEN window_reset THEN 1 ELSE (old_row->>'admitted')::bigint+1 END,'updated_at',p_tx_at);
     images:=images||kaname._authority_crud_image_v3(command_no,'identity_admission_windows','UPDATE',old_row,new_row);
    END IF;
   END IF;
  END IF;
 END IF;
 RETURN images;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Auxiliary row guards не покрывают TRUNCATE. Для CRUD он запрещён,
-- а каждый INSERT/UPDATE/DELETE должен принадлежать текущей exact команде.
-- Существующие maintenance/compatibility операции без CRUD claim сохраняются.
CREATE FUNCTION kaname._authority_crud_aux_statement_v3() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;allowed boolean;
BEGIN
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_LEVEL<>'STATEMENT' OR TG_WHEN<>'BEFORE'
 OR TG_TABLE_NAME NOT IN ('issued_account_ids','project_resource_quotas','identity_admission_windows',
  'role_grant_orphan','role_selector_prune','resource_journal') THEN
  RAISE EXCEPTION 'invalid CRUD auxiliary statement graph' USING ERRCODE='42501';END IF;
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NULL OR manifest->'intent'->>'kind' IS DISTINCT FROM 'crud' THEN RETURN NULL;END IF;
 IF manifest->>'state' IS DISTINCT FROM 'body' OR manifest->>'registration_program_claimed' IS DISTINCT FROM 'true' OR TG_OP='TRUNCATE' THEN
  RAISE EXCEPTION 'CRUD auxiliary statement outside current command' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='resource_journal' THEN
  allowed:=TG_OP='INSERT' AND EXISTS(SELECT 1 FROM jsonb_array_elements(manifest#>'{registration_physical,journal}') e
   WHERE e->'command'=manifest->'object_command');
 ELSE
  allowed:=EXISTS(SELECT 1 FROM jsonb_array_elements(manifest#>'{registration_program,commands}') WITH ORDINALITY q(step,ordinal)
   WHERE ordinal=(manifest->>'object_command')::integer AND coalesce(step->'operations'->TG_TABLE_NAME,'[]'::jsonb) ? TG_OP);
 END IF;
 IF NOT coalesce(allowed,false) THEN RAISE EXCEPTION 'CRUD auxiliary statement not compiled' USING ERRCODE='42501';END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Read-only RR вход возвращает только graph, доступный original LOGIN.
-- Helper не возвращает attestation, nonce, body program или credential rows.
CREATE FUNCTION kaname.authority_resource_crud_capture_v3(p_intent jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE captured jsonb;descriptor jsonb;tables jsonb;entry record;invoker oid;relation_id oid;column_name text;
BEGIN
 descriptor:=kaname._authority_crud_intent_v3(p_intent);
 IF current_setting('transaction_isolation')<>'repeatable read' OR current_setting('transaction_read_only')<>'on' THEN
  RAISE EXCEPTION 'CRUD stage requires read-only RR transaction' USING ERRCODE='42501';END IF;
 SELECT oid INTO STRICT invoker FROM pg_catalog.pg_roles
 WHERE rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
 IF NOT has_schema_privilege(invoker,'kaname','USAGE') THEN RAISE EXCEPTION 'CRUD capture schema usage required' USING ERRCODE='42501';END IF;
 captured:=kaname._authority_crud_capture_v3(p_intent,p_rows,p_reads);
 tables:=kaname._authority_crud_merge_tables_v3(captured#>'{sources,tables}',captured#>'{sources,authority_graph}');
 tables:=kaname._authority_crud_merge_tables_v3(tables,captured#>'{sources,journal_sources}');
 tables:=tables||jsonb_build_object(descriptor->>'table',coalesce(tables->(descriptor->>'table'),'[]'::jsonb));
 IF captured#>'{sources,parent,row}'<>'null'::jsonb THEN tables:=tables||jsonb_build_object('accounts',coalesce(tables->'accounts','[]'::jsonb));END IF;
 IF captured#>'{sources,owner,row}'<>'null'::jsonb THEN tables:=tables||jsonb_build_object('users',coalesce(tables->'users','[]'::jsonb));END IF;
 FOR entry IN SELECT * FROM jsonb_each(tables) LOOP
  relation_id:=to_regclass(format('kaname.%I',entry.key));
  IF relation_id IS NULL THEN RAISE EXCEPTION 'CRUD capture relation missing' USING ERRCODE='42501';END IF;
  IF entry.key='service_account_oauth_clients' THEN
   -- RESTRICT footprint содержит только FK identity, ни client secret,
   -- ни hash здесь не выбирается и не возвращается.
   FOREACH column_name IN ARRAY ARRAY['id','sva_id'] LOOP
    IF NOT has_column_privilege(invoker,relation_id,column_name,'SELECT') THEN
     RAISE EXCEPTION 'CRUD capture requires original FK column SELECT' USING ERRCODE='42501';END IF;
   END LOOP;
  ELSIF NOT has_table_privilege(invoker,relation_id,'SELECT') THEN
   RAISE EXCEPTION 'CRUD capture requires original table SELECT' USING ERRCODE='42501';END IF;
 END LOOP;
 RETURN captured;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Полный bounded RR capture собирается из закрытых частей. Источник
-- повторяется в нескольких слоях одного STABLE snapshot. Точный UNION
-- сохраняет row/xmin/ctid для последующего обязательного reread.
CREATE FUNCTION kaname._authority_crud_merge_tables_v3(p_left jsonb,p_right jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE result jsonb:=p_left;entry record;merged jsonb;row_value jsonb;
BEGIN
 IF jsonb_typeof(p_left) IS DISTINCT FROM 'object' OR jsonb_typeof(p_right) IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'CRUD captured table set invalid' USING ERRCODE='42501';END IF;
 FOR entry IN SELECT * FROM jsonb_each(p_right) LOOP
  IF jsonb_typeof(entry.value) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'CRUD captured table missing' USING ERRCODE='42501';END IF;
  SELECT coalesce(jsonb_agg(value ORDER BY value::text COLLATE "C"),'[]'::jsonb) INTO merged FROM (
   SELECT DISTINCT value FROM jsonb_array_elements(coalesce(result->entry.key,'[]'::jsonb)||entry.value)
  ) rows_value;
  IF jsonb_array_length(merged)>100000 THEN RAISE EXCEPTION 'CRUD merged source budget exceeded' USING ERRCODE='54000';END IF;
  result:=result||jsonb_build_object(entry.key,merged);
 END LOOP;
 RETURN result;
END $$;

CREATE FUNCTION kaname._authority_crud_capture_v3(p_intent jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE captured jsonb;part jsonb;sources jsonb;tables jsonb:='{}';program jsonb;fold_sources jsonb;
 used_rows integer:=0;used_reads integer:=0;
BEGIN
 captured:=kaname._authority_crud_anchor_capture_v3(p_intent,p_rows,p_reads);
 sources:=captured->'sources';used_rows:=(captured->>'logical_rows')::integer;used_reads:=(captured->>'logical_reads')::integer;
 part:=kaname._authority_crud_scope_capture_v3(p_intent,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+(part->>'logical_rows')::integer;used_reads:=used_reads+(part->>'logical_reads')::integer;
 tables:=kaname._authority_crud_merge_tables_v3(tables,part->'tables');
 sources:=sources||(part-ARRAY['tables','logical_rows','logical_reads']);
 part:=kaname._authority_crud_cascade_capture_v3(p_intent,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+(part->>'logical_rows')::integer;used_reads:=used_reads+(part->>'logical_reads')::integer;
 tables:=kaname._authority_crud_merge_tables_v3(tables,part->'tables');
 part:=kaname._authority_crud_aux_capture_v3(p_intent,sources,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+(part->>'logical_rows')::integer;used_reads:=used_reads+(part->>'logical_reads')::integer;
 tables:=kaname._authority_crud_merge_tables_v3(tables,part->'tables');
 sources:=sources||(part-ARRAY['tables','logical_rows','logical_reads']);
 program:=kaname._authority_crud_command_plan_v3(p_intent,sources);
 fold_sources:=kaname._authority_crud_fold_capture_v3(program,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+(fold_sources->>'logical_rows')::integer;used_reads:=used_reads+(fold_sources->>'logical_reads')::integer;
 tables:=kaname._authority_crud_merge_tables_v3(tables,fold_sources->'tables');
 sources:=sources||jsonb_build_object('tables',tables,'fold',fold_sources-ARRAY['logical_rows','logical_reads']);
 part:=kaname._authority_crud_journal_capture_v3(p_intent,sources,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+(part->>'logical_rows')::integer;used_reads:=used_reads+(part->>'logical_reads')::integer;
 sources:=sources||jsonb_build_object('journal_sources',part->'tables');
 part:=kaname._authority_crud_authority_graph_v3(p_intent,sources,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+(part->>'logical_rows')::integer;used_reads:=used_reads+(part->>'logical_reads')::integer;
 sources:=sources||jsonb_build_object('authority_graph',part->'tables');
 IF used_rows>p_rows OR used_reads>p_reads OR octet_length(sources::text)>67108864 THEN
  RAISE EXCEPTION 'CRUD aggregate capture budget exceeded' USING ERRCODE='54000';END IF;
 RETURN captured||jsonb_build_object('sources',sources,'logical_rows',used_rows,'logical_reads',used_reads);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- FK/cascade capture закрытой семёрки. Служебные credential строки не
-- экспортируются: для RESTRICT достаточно ID/sva_id/xmin и future row prelock.
CREATE FUNCTION kaname._authority_crud_cascade_capture_v3(p_intent jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE descriptor jsonb;wanted text[];table_name text;predicate text;projection text;target_id text;
 tables jsonb:='{}'::jsonb;rows_value jsonb;count_rows integer;used_rows integer:=0;used_reads integer:=0;
BEGIN
 descriptor:=kaname._authority_crud_intent_v3(p_intent);target_id:=descriptor->>'id';
 IF p_rows IS NULL OR p_rows<0 OR p_rows>100000 OR p_reads IS NULL OR p_reads<0 OR p_reads>4096 THEN
  RAISE EXCEPTION 'CRUD cascade capture budget exceeded' USING ERRCODE='54000';END IF;
 CASE descriptor->>'command'
 WHEN 'account.delete' THEN wanted:=ARRAY['users'];
 WHEN 'role.delete' THEN wanted:=ARRAY['access_binding_target_members','role_rule_selectors','role_selector_verbs_pending',
  'role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule','role_grant_orphan','role_selector_prune'];
 WHEN 'service_account.delete' THEN wanted:=ARRAY['service_account_oauth_clients'];
 ELSE wanted:=ARRAY[]::text[];
 END CASE;
 FOREACH table_name IN ARRAY wanted LOOP
  IF used_reads>=p_reads THEN RAISE EXCEPTION 'CRUD cascade read budget exceeded' USING ERRCODE='54000';END IF;
  projection:='to_jsonb(t)';
  CASE table_name
  WHEN 'users' THEN predicate:='t.account_id=$1';
  WHEN 'role_bind_role_rule' THEN predicate:='t.role_id=$1 OR t.bound_role_id=$1';
  WHEN 'service_account_oauth_clients' THEN
   predicate:='t.sva_id=$1';projection:='jsonb_build_object(''id'',t.id,''sva_id'',t.sva_id)';
  ELSE predicate:='t.role_id=$1';
  END CASE;
  EXECUTE format('SELECT coalesce(jsonb_agg(jsonb_build_object(''row'',row_value,''xmin'',xmin_value,''ctid'',ctid_value)
   ORDER BY row_value::text COLLATE "C"),''[]''::jsonb)
   FROM (SELECT %s row_value,t.xmin::text xmin_value,t.ctid::text ctid_value FROM ONLY kaname.%I t
    WHERE %s ORDER BY %s::text COLLATE "C" LIMIT $2) current_rows',projection,table_name,predicate,projection)
  INTO rows_value USING target_id,p_rows-used_rows+1;
  count_rows:=jsonb_array_length(rows_value);used_reads:=used_reads+1;
  IF count_rows>p_rows-used_rows THEN RAISE EXCEPTION 'CRUD cascade row budget exceeded' USING ERRCODE='54000';END IF;
  used_rows:=used_rows+count_rows;tables:=tables||jsonb_build_object(table_name,rows_value);
 END LOOP;
 RETURN jsonb_build_object('tables',tables,'logical_rows',used_rows,'logical_reads',used_reads);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- SOURCE ONLY: private state/nonce/ABI остаются общими с Resource.
-- Этот фрагмент ещё не является полной append migration.
CREATE FUNCTION kaname.authority_resource_crud_body_values_v3() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;commands jsonb;
BEGIN
 manifest:=kaname._authority_resource_manifest_v2();
 IF manifest->>'state' IS DISTINCT FROM 'body' OR manifest->'intent'->>'kind' IS DISTINCT FROM 'crud'
 OR coalesce(manifest->'intent'->>'command','') NOT IN ('account.create','account.delete','project.create','project.delete','service_account.create','service_account.delete','role.delete')
 OR manifest->>'registration_program_claimed' IS DISTINCT FROM 'false'
 OR manifest->>'transaction_at' IS NULL OR manifest->>'decision_at' IS NULL THEN
  RAISE EXCEPTION 'private CRUD body unavailable' USING ERRCODE='42501';END IF;
 commands:=manifest#>'{registration_program,commands}';
 IF jsonb_typeof(commands) IS DISTINCT FROM 'array' OR jsonb_array_length(commands)<1 OR jsonb_array_length(commands)>100000 THEN
  RAISE EXCEPTION 'invalid private CRUD program' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_authority_resource_manifest SET registration_program_claimed=true;
 RETURN jsonb_build_object('transaction_at',manifest->'transaction_at','decision_at',manifest->'decision_at');
END $$;

CREATE FUNCTION kaname._authority_crud_step_complete_v3(manifest jsonb,p_step integer) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE obligations jsonb;field text;actual jsonb;
BEGIN
 IF manifest->'intent'->>'kind' IS DISTINCT FROM 'crud' OR p_step IS NULL OR p_step<1
 OR p_step>jsonb_array_length(manifest#>'{registration_program,commands}')
 OR manifest->>'state' IS DISTINCT FROM 'body' THEN
  RAISE EXCEPTION 'invalid CRUD completion step' USING ERRCODE='42501';END IF;
 obligations:=manifest->'registration_step_obligations'->p_step::text;
 IF jsonb_typeof(obligations) IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'CRUD step obligations absent' USING ERRCODE='42501';END IF;
 FOREACH field IN ARRAY ARRAY['writes','audits','folds','bindings','reconcile','subject_changes','journal','fga_ids','aux'] LOOP
  actual:=CASE field WHEN 'writes' THEN manifest->'consumed_required_writes'
   WHEN 'audits' THEN manifest->'consumed_audit_ids'
   WHEN 'folds' THEN manifest->'consumed_object_folds'
   WHEN 'bindings' THEN manifest->'consumed_registration_bindings'
   WHEN 'reconcile' THEN manifest->'consumed_reconcile_ids'
   WHEN 'subject_changes' THEN manifest->'consumed_subject_change_ids'
   WHEN 'journal' THEN manifest#>'{registration_body,consumed_journal_ids}'
   WHEN 'fga_ids' THEN manifest#>'{registration_body,consumed_fga_ids}'
   WHEN 'aux' THEN manifest#>'{registration_body,consumed_aux}' END;
  IF jsonb_typeof(obligations->field) IS DISTINCT FROM 'array' OR jsonb_typeof(actual) IS DISTINCT FROM 'array'
  OR NOT actual @> (obligations->field) THEN
   RAISE EXCEPTION 'CRUD command mandatory effects are incomplete' USING ERRCODE='42501';END IF;
 END LOOP;
END $$;

CREATE FUNCTION kaname.authority_resource_crud_step_v3(p_kind text,p_request jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;ordinal integer;command jsonb;
BEGIN
 manifest:=kaname._authority_resource_manifest_v2();
 ordinal:=(manifest->>'object_command')::integer+1;
 IF manifest->>'state' IS DISTINCT FROM 'body' OR manifest->'intent'->>'kind' IS DISTINCT FROM 'crud'
 OR manifest->>'registration_program_claimed' IS DISTINCT FROM 'true'
 OR ordinal IS NULL OR ordinal<1 OR ordinal>jsonb_array_length(manifest#>'{registration_program,commands}') THEN
  RAISE EXCEPTION 'CRUD command is not a next private step' USING ERRCODE='42501';END IF;
 command:=manifest#>'{registration_program,commands}'->(ordinal-1);
 -- Caller сообщает только фактический вызов API; права/row images/ключи
 -- возвращаются из private программы, которую построил сервер до clock.
 IF p_kind IS NULL OR command->>'kind' IS DISTINCT FROM p_kind
 OR p_request IS NULL OR command->'request' IS DISTINCT FROM p_request THEN
  RAISE EXCEPTION 'CRUD command request differs from prepared operation' USING ERRCODE='42501';END IF;
 IF ordinal>1 THEN PERFORM kaname._authority_crud_step_complete_v3(manifest,ordinal-1);END IF;
 UPDATE pg_temp.kaname_authority_resource_manifest SET object_command=ordinal;
 RETURN command-ARRAY['request','operations'];
END $$;

CREATE FUNCTION kaname.authority_resource_crud_lock_held_v3(p_key text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;hashed integer;
BEGIN
 manifest:=kaname._authority_resource_manifest_v2();
 IF manifest->'intent'->>'kind' IS DISTINCT FROM 'crud' OR manifest->>'state' IS DISTINCT FROM 'body'
 OR p_key IS NULL OR NOT coalesce((manifest#>'{registration_body,held_legacy_keys}') ? p_key,false) THEN
  RAISE EXCEPTION 'CRUD legacy lock was not prepared' USING ERRCODE='42501';END IF;
 hashed:=hashtext(p_key);
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_backend_pid()
  AND l.database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
  AND l.locktype='advisory' AND l.classid=(CASE WHEN hashed<0 THEN 4294967295 ELSE 0 END)::oid
  AND l.objid=(hashed::bigint & 4294967295)::oid AND l.objsubid=1 AND l.mode='ExclusiveLock' AND l.granted) THEN
  RAISE EXCEPTION 'CRUD legacy lock no longer held' USING ERRCODE='42501';END IF;
END $$;

CREATE FUNCTION kaname._authority_crud_require_completion_v3(manifest jsonb) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE physical jsonb;planned jsonb;consumed jsonb;field text;ordinal integer;commands integer;
BEGIN
 commands:=jsonb_array_length(manifest#>'{registration_program,commands}');
 IF manifest->'intent'->>'kind' IS DISTINCT FROM 'crud' OR manifest->>'state' IS DISTINCT FROM 'body'
 OR manifest->>'registration_program_claimed' IS DISTINCT FROM 'true' OR commands IS NULL OR commands<1 OR commands>100000
 OR (manifest->>'object_command')::integer IS DISTINCT FROM commands THEN
  RAISE EXCEPTION 'CRUD program not completed' USING ERRCODE='42501';END IF;
 FOR ordinal IN 1..commands LOOP PERFORM kaname._authority_crud_step_complete_v3(manifest,ordinal);END LOOP;
 physical:=manifest->'registration_physical';
 FOREACH field IN ARRAY ARRAY['audits','reconcile','subject_changes','journal'] LOOP
  consumed:=CASE field WHEN 'audits' THEN manifest->'consumed_audit_ids'
   WHEN 'reconcile' THEN manifest->'consumed_reconcile_ids'
   WHEN 'subject_changes' THEN manifest->'consumed_subject_change_ids'
   ELSE manifest#>'{registration_body,consumed_journal_ids}' END;
  SELECT coalesce(jsonb_agg(CASE WHEN field='journal' THEN value->'row'->'sequence_no' ELSE value->'row'->'id' END),'[]'::jsonb)
   INTO planned FROM jsonb_array_elements(physical->field);
  IF jsonb_typeof(physical->field) IS DISTINCT FROM 'array' OR jsonb_typeof(consumed) IS DISTINCT FROM 'array'
  OR jsonb_array_length(planned)<>jsonb_array_length(consumed) OR NOT consumed @> planned
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(consumed) x GROUP BY x HAVING count(*)<>1) THEN
   RAISE EXCEPTION 'CRUD auxiliary effect omitted or repeated' USING ERRCODE='42501';END IF;
 END LOOP;
 SELECT coalesce(jsonb_agg(entry->'id'),'[]'::jsonb) INTO planned
 FROM jsonb_array_elements(physical->'outboxes') entry;
 consumed:=manifest#>'{registration_body,consumed_fga_ids}';
 IF jsonb_typeof(consumed) IS DISTINCT FROM 'array'
 OR jsonb_array_length(planned)<>jsonb_array_length(consumed) OR NOT consumed @> planned
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(consumed) x GROUP BY x HAVING count(*)<>1) THEN
  RAISE EXCEPTION 'CRUD FGA reserved ID omitted or repeated' USING ERRCODE='42501';END IF;
 IF (manifest#>'{registration_body,claimed_journal_ids}') IS DISTINCT FROM (manifest#>'{registration_body,consumed_journal_ids}') THEN
  RAISE EXCEPTION 'CRUD claimed journal effect was not inserted' USING ERRCODE='42501';END IF;
 SELECT coalesce(jsonb_agg(position),'[]'::jsonb) INTO planned
 FROM jsonb_array_elements(physical->'aux') WITH ORDINALITY e(value,position) WHERE value->>'required'='true';
 consumed:=manifest#>'{registration_body,consumed_aux}';
 IF jsonb_typeof(physical->'aux') IS DISTINCT FROM 'array' OR jsonb_typeof(consumed) IS DISTINCT FROM 'array'
 OR jsonb_array_length(planned)<>jsonb_array_length(consumed) OR NOT consumed @> planned
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(consumed) x GROUP BY x HAVING count(*)<>1) THEN
  RAISE EXCEPTION 'CRUD auxiliary row omitted or repeated' USING ERRCODE='42501';END IF;
 -- Основные exact writes/folds проверяет общий Resource completion trigger.
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Чистая последовательность actual UC вызовов. Перед использованием sources
-- повторно подтверждаются private prewait; сами эти JSON не являются proof.
CREATE FUNCTION kaname._authority_crud_command_v3(p_kind text,p_request jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF p_kind IS NULL OR p_kind NOT IN ('account.insert','account.delete','project.insert','project.delete',
  'service_account.insert','service_account.delete','role.delete','binding.insert','binding.delete',
  'binding.subjects','binding.ledger','binding.audit','audit','reconcile','fga.tuple.write','fga.tuple.delete')
 OR p_request IS NULL THEN RAISE EXCEPTION 'invalid closed CRUD step' USING ERRCODE='42501';END IF;
 RETURN jsonb_build_array(jsonb_build_object('kind',p_kind,'request',p_request));
END $$;

CREATE FUNCTION kaname._authority_crud_structural_v3(p_kind text,p_id text,p_account text,p_owner text DEFAULT '')
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE result jsonb;
BEGIN
 IF p_id IS NULL OR p_id='' THEN RAISE EXCEPTION 'missing structural ID' USING ERRCODE='42501';END IF;
 IF p_kind='project' THEN
  result:=jsonb_build_array(jsonb_build_object('User','cluster:cluster_root','Relation','cluster','Object','project:'||p_id));
  IF coalesce(p_account,'')<>'' THEN result:=result||jsonb_build_array(jsonb_build_object('User','account:'||p_account,'Relation','account','Object','project:'||p_id));END IF;
 ELSIF p_kind='account' THEN
  result:=jsonb_build_array(jsonb_build_object('User','cluster:cluster_root','Relation','cluster','Object','account:'||p_id));
  IF coalesce(p_owner,'')<>'' THEN result:=result||jsonb_build_array(jsonb_build_object('User','user:'||p_owner,'Relation','owner','Object','account:'||p_id));END IF;
 ELSIF p_kind='service_account' AND coalesce(p_account,'')<>'' THEN
  result:=jsonb_build_array(jsonb_build_object('User','account:'||p_account,'Relation','account','Object','iam_service_account:'||p_id));
 ELSE RAISE EXCEPTION 'unsupported CRUD structural kind' USING ERRCODE='42501';END IF;
 RETURN result;
END $$;

CREATE FUNCTION kaname._authority_crud_command_plan_v3(p_intent jsonb,p_sources jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE descriptor jsonb;command text;target_id text;account_id text;actor_id text;kind text;dotted text;
 commands jsonb:='[]'::jsonb;payload jsonb;audit_request jsonb;binding jsonb;ledger jsonb;deletes jsonb:='[]'::jsonb;
 member jsonb;input jsonb;project_input jsonb;binding_id text;owner_id text;hierarchy jsonb;owner_tuple jsonb;
BEGIN
 descriptor:=kaname._authority_crud_intent_v3(p_intent);command:=descriptor->>'command';target_id:=descriptor->>'id';
 actor_id:=split_part(descriptor->>'actor',':',2);input:=p_intent->'input';
 IF jsonb_typeof(p_sources) IS DISTINCT FROM 'object' OR p_sources->'descriptor' IS DISTINCT FROM descriptor THEN
  RAISE EXCEPTION 'CRUD command source descriptor mismatch' USING ERRCODE='42501';END IF;
 kind:=split_part(command,'.',1);dotted:=CASE kind WHEN 'service_account' THEN 'iam.serviceAccount' ELSE 'iam.'||kind END;
 account_id:=CASE WHEN kind='account' THEN target_id WHEN command LIKE '%.create' THEN descriptor->>'account'
  ELSE p_sources#>>'{primary,row,account_id}' END;
 IF coalesce(account_id,'')='' AND command<>'role.delete' THEN RAISE EXCEPTION 'CRUD command account missing' USING ERRCODE='42501';END IF;
 -- Role audit исторически хранит именно role.AccountID; у project/cluster
 -- definition он пуст, а authority scope выводится отдельно из OLD graph.
 account_id:=coalesce(account_id,'');
 payload:=jsonb_build_object('actor',actor_id,'resource_type',kind,'resource_id',target_id);
 IF kind<>'account' THEN payload:=payload||jsonb_build_object('account_id',account_id);END IF;
 IF command LIKE '%.create' THEN payload:=payload||jsonb_build_object('name',CASE WHEN kind='account' THEN input#>>'{Account,Name}' ELSE input->>'Name' END);END IF;
 IF command='account.create' THEN payload:=payload||jsonb_build_object('id_source',input->>'IDSource');END IF;
 audit_request:=jsonb_build_object('EventType','iam.'||kind||CASE WHEN command LIKE '%.create' THEN '.created' ELSE '.deleted' END,
  'TenantAccountID',account_id,'Payload',payload);
 IF command='account.create' THEN
  binding_id:=input->>'OwnerBindingID';owner_id:=input#>>'{Account,OwnerUserID}';
  project_input:=jsonb_build_object('ID',input->>'DefaultProjectID','AccountID',target_id,'Name','default',
   'Description','','Labels','{}'::jsonb,'CreatedAt','0001-01-01T00:00:00Z');
  commands:=commands||kaname._authority_crud_command_v3('account.insert',input->'Account')
   ||kaname._authority_crud_command_v3('project.insert',project_input)
   ||kaname._authority_crud_command_v3('fga.tuple.write',kaname._authority_crud_structural_v3('project',input->>'DefaultProjectID',target_id))
   ||kaname._authority_crud_command_v3('reconcile',jsonb_build_object('EventType','mirror.upsert','ObjectType','iam.project','ObjectID',input->>'DefaultProjectID'))
   ||kaname._authority_crud_command_v3('audit',audit_request)
   ||kaname._authority_crud_command_v3('fga.tuple.write',kaname._authority_crud_structural_v3('account',target_id,'',owner_id))
   ||kaname._authority_crud_command_v3('binding.insert',to_jsonb(binding_id))
   ||kaname._authority_crud_command_v3('binding.subjects',jsonb_build_object('ID',binding_id,'Subjects',
    jsonb_build_array(jsonb_build_object('Type','user','ID',owner_id))));
  hierarchy:=jsonb_build_array(jsonb_build_object('User','account:'||target_id,'Relation','account','Object','iam_access_binding:'||binding_id));
  owner_tuple:=jsonb_build_array(jsonb_build_object('User','user:'||owner_id,'Relation','owner','Object','account:'||target_id));
  commands:=commands||kaname._authority_crud_command_v3('fga.tuple.write',hierarchy)
   ||kaname._authority_crud_command_v3('binding.ledger',jsonb_build_object('ID',binding_id,'Tuples',owner_tuple||hierarchy))
   ||kaname._authority_crud_command_v3('binding.audit',jsonb_build_object('EventType','iam.access_binding.granted',
    'Actor',actor_id,'SubjectType','user','SubjectID',owner_id,'ResourceType','account','ResourceID',target_id,
    'RoleID','rol72122ce96bfec66e2','BindingID',binding_id,'TenantAccountID',target_id,'ExtraPayload',NULL));
 ELSIF command IN ('project.create','service_account.create') THEN
  commands:=commands||kaname._authority_crud_command_v3(kind||'.insert',input)
   ||kaname._authority_crud_command_v3('audit',audit_request)
   ||kaname._authority_crud_command_v3('fga.tuple.write',kaname._authority_crud_structural_v3(kind,target_id,account_id))
   ||kaname._authority_crud_command_v3('reconcile',jsonb_build_object('EventType','mirror.upsert','ObjectType',dotted,'ObjectID',target_id));
 ELSE
  IF command IN ('account.delete','project.delete') THEN
   IF jsonb_typeof(p_sources->'scope_bindings') IS DISTINCT FROM 'array'
   OR jsonb_typeof(p_sources->'binding_ledger') IS DISTINCT FROM 'object'
   OR jsonb_array_length(p_sources->'scope_bindings')>=50000 THEN
    RAISE EXCEPTION 'CRUD binding drain source missing or exceeds actual UC passes' USING ERRCODE='54000';END IF;
   -- ListByScope страницы идут created_at,id; внутри каждой страницы actual
   -- drain сортирует ID. Capture сохраняет именно этот порядок, не global ID.
   FOR binding IN SELECT value FROM jsonb_array_elements(p_sources->'scope_bindings') LOOP
    IF binding->>'resource_type' IS DISTINCT FROM kind OR binding->>'resource_id' IS DISTINCT FROM target_id
    OR coalesce(binding->>'id','')='' THEN RAISE EXCEPTION 'CRUD scope binding mismatch' USING ERRCODE='42501';END IF;
    ledger:=p_sources->'binding_ledger'->(binding->>'id');
    IF jsonb_typeof(ledger) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'CRUD persisted ledger missing' USING ERRCODE='42501';END IF;
    deletes:=deletes||ledger;
    commands:=commands||kaname._authority_crud_command_v3('binding.delete',binding->'id')
     ||kaname._authority_crud_command_v3('reconcile',jsonb_build_object('EventType','mirror.delete','ObjectType','iam.accessBinding','ObjectID',binding->>'id'));
   END LOOP;
  END IF;
  IF command='account.delete' THEN
   deletes:=deletes||jsonb_build_array(jsonb_build_object('User','cluster:cluster_root','Relation','cluster','Object','account:'||target_id));
   commands:=commands||kaname._authority_crud_command_v3('fga.tuple.delete',deletes)
    ||kaname._authority_crud_command_v3('account.delete',to_jsonb(target_id));
   IF jsonb_typeof(p_sources->'membership_user_ids') IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'CRUD account membership source missing' USING ERRCODE='42501';END IF;
   deletes:='[]'::jsonb;
   FOR member IN SELECT value FROM jsonb_array_elements(p_sources->'membership_user_ids') LOOP
    deletes:=deletes||jsonb_build_array(jsonb_build_object('User','account:'||target_id,'Relation','account','Object','iam_user:'||(member#>>'{}')));
   END LOOP;
   commands:=commands||kaname._authority_crud_command_v3('fga.tuple.delete',deletes);
  ELSE
   commands:=commands||kaname._authority_crud_command_v3(kind||'.delete',to_jsonb(target_id));
   IF command='project.delete' THEN
    commands:=commands||kaname._authority_crud_command_v3('fga.tuple.delete',deletes||kaname._authority_crud_structural_v3('project',target_id,account_id));
   END IF;
  END IF;
  commands:=commands||kaname._authority_crud_command_v3('reconcile',jsonb_build_object('EventType','mirror.delete','ObjectType',dotted,'ObjectID',target_id))
   ||kaname._authority_crud_command_v3('audit',audit_request);
 END IF;
 IF jsonb_array_length(commands)>100000 THEN RAISE EXCEPTION 'CRUD program command budget exceeded' USING ERRCODE='54000';END IF;
 RETURN jsonb_build_object('commands',commands);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_resource_assert_body_v2(p_intent jsonb) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;
BEGIN
 manifest:=kaname._authority_resource_manifest_v2();
 IF manifest->>'state' IS DISTINCT FROM 'final' OR p_intent IS DISTINCT FROM manifest->'intent'
 OR manifest->>'decision_at' IS NULL THEN
  RAISE EXCEPTION 'resource closed body requires final manifest' USING ERRCODE='42501';
 END IF;
 -- Resource не является writer личности или каталога. Проверка действует
 -- до смены state на body: даже ошибочный private creator не может включить
 -- SA INSERT/DELETE/reparent и обойти GLOBAL/root защиту absence witness.
 -- Точные разрешённые OLD/NEW оставшихся таблиц дополнительно проверяет
 -- semantic creator; принадлежность этому перечню сама по себе не allow.
 IF manifest->'intent'->>'kind'='crud' THEN
  PERFORM kaname._authority_crud_manifest_domain_v3(manifest);
 ELSE
 IF jsonb_typeof(manifest->'writes') IS DISTINCT FROM 'array'
 OR jsonb_array_length(manifest->'writes')>100000
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(manifest->'writes') w
  WHERE coalesce(w->>'table','') NOT IN (
   'roles','access_bindings','access_binding_subjects','access_binding_target_members','access_binding_emitted_tuples',
   'role_rule_selectors','role_selector_verbs_pending','role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule',
   'resource_mirror','resource_parent_edge','resource_registration_scope','resource_registration_pointer',
   'resource_registration_retirement','producer_source_receipt','public_read_publication','relation_fact','fga_outbox')) THEN
  RAISE EXCEPTION 'resource manifest contains unsupported write domain' USING ERRCODE='42501';
 END IF;
 END IF;
 -- Второй запуск того же тела в одной TX также отвергается. Изменение
 -- касается только уже открытой private temp строки, новых waits нет.
 UPDATE pg_temp.kaname_authority_resource_manifest SET state='body';
 RETURN true;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_resource_require_completion_v2() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb; physical jsonb; storage oid; consumed integer[]; required_count integer; consumed_count integer;
BEGIN
 storage:=to_regclass('pg_temp.kaname_authority_resource_manifest');
 IF TG_RELID IS DISTINCT FROM storage OR TG_OP<>'INSERT' OR TG_WHEN<>'AFTER'
 OR TG_LEVEL<>'ROW' OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c
  WHERE c.oid=storage AND c.relowner=current_user::regrole::oid AND c.relpersistence='t' AND c.relkind='r') THEN
  RAISE EXCEPTION 'resource completion trigger target invalid' USING ERRCODE='42501';
 END IF;
 manifest:=kaname._authority_resource_manifest_v2();
 IF manifest->>'state' IS DISTINCT FROM 'body'
 OR jsonb_typeof(manifest->'writes') IS DISTINCT FROM 'array'
 OR jsonb_array_length(manifest->'writes')>100000 THEN
  RAISE EXCEPTION 'resource body did not complete' USING ERRCODE='42501';
 END IF;
 SELECT consumed_required_writes INTO STRICT consumed FROM pg_temp.kaname_authority_resource_manifest;
 IF consumed IS NULL OR cardinality(consumed)>100000
 OR EXISTS(SELECT 1 FROM unnest(consumed) n WHERE n IS NULL OR n<1 OR n>jsonb_array_length(manifest->'writes'))
 OR EXISTS(SELECT 1 FROM unnest(consumed) n GROUP BY n HAVING count(*)<>1)
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(manifest->'writes') w WHERE jsonb_typeof(w->'required') IS DISTINCT FROM 'boolean') THEN
  RAISE EXCEPTION 'resource completion inventory is invalid' USING ERRCODE='42501';
 END IF;
 SELECT count(*)::integer INTO required_count FROM jsonb_array_elements(manifest->'writes') w WHERE w->>'required'='true';
 SELECT count(*)::integer INTO consumed_count FROM unnest(consumed) n
  WHERE manifest->'writes'->(n-1)->>'required'='true';
 IF required_count<>consumed_count THEN
  RAISE EXCEPTION 'resource mandatory effect was omitted' USING ERRCODE='42501';
 END IF;
 -- Audit и вспомогательные очереди не входят в authority32; их точное
 -- применение и завершение последней команды проверяются отдельно.
 IF manifest->'intent'->>'kind'='object' THEN
  IF manifest->>'object_program_claimed' IS DISTINCT FROM 'true'
   OR (manifest->>'object_command')::integer IS DISTINCT FROM jsonb_array_length(manifest#>'{object_program,commands}') THEN
   RAISE EXCEPTION 'resource object program did not complete' USING ERRCODE='42501';END IF;
  physical:=manifest->'object_physical';
 ELSIF manifest->'intent'->>'kind'='crud' THEN
  PERFORM kaname._authority_crud_manifest_domain_v3(manifest);
  PERFORM kaname._authority_crud_require_completion_v3(manifest);
  physical:=manifest->'registration_physical';
 ELSIF manifest->'intent'->>'Action' IN ('1','2','3','4','5') THEN
  IF manifest->>'registration_program_claimed' IS DISTINCT FROM 'true'
   OR (manifest->>'object_command')::integer IS DISTINCT FROM jsonb_array_length(manifest#>'{registration_program,commands}') THEN
   RAISE EXCEPTION 'resource registration program did not complete' USING ERRCODE='42501';END IF;
  physical:=manifest->'registration_physical';
  IF jsonb_typeof(physical->'bindings') IS DISTINCT FROM 'array'
   OR jsonb_typeof(physical->'reconcile') IS DISTINCT FROM 'array'
   OR jsonb_typeof(manifest->'consumed_registration_bindings') IS DISTINCT FROM 'array'
   OR jsonb_typeof(manifest->'consumed_reconcile_ids') IS DISTINCT FROM 'array'
   OR jsonb_typeof(physical->'subject_changes') IS DISTINCT FROM 'array'
   OR jsonb_typeof(manifest->'consumed_subject_change_ids') IS DISTINCT FROM 'array'
   OR jsonb_array_length(physical->'subject_changes')<>jsonb_array_length(manifest->'consumed_subject_change_ids')
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(physical->'subject_changes') r
    WHERE NOT (manifest->'consumed_subject_change_ids') @> jsonb_build_array(r->'row'->'id'))
   OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_subject_change_ids') n GROUP BY n HAVING count(*)<>1)
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(physical->'bindings') WITH ORDINALITY e(value,ordinality)
    WHERE e.value->>'required'='true' AND NOT (manifest->'consumed_registration_bindings') @> jsonb_build_array(e.ordinality))
   OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_registration_bindings') n
    WHERE n::integer<1 OR n::integer>jsonb_array_length(physical->'bindings')
     OR physical->'bindings'->(n::integer-1)->>'required' IS DISTINCT FROM 'true')
   OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_registration_bindings') n GROUP BY n HAVING count(*)<>1)
   OR jsonb_array_length(physical->'reconcile')<>jsonb_array_length(manifest->'consumed_reconcile_ids')
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(physical->'reconcile') r
    WHERE NOT (manifest->'consumed_reconcile_ids') @> jsonb_build_array(r->'row'->'id'))
   OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_reconcile_ids') n GROUP BY n HAVING count(*)<>1) THEN
    RAISE EXCEPTION 'resource registration auxiliary effect omitted' USING ERRCODE='42501';END IF;
 ELSE RAISE EXCEPTION 'resource completion intent unsupported' USING ERRCODE='42501';
 END IF;
 IF jsonb_typeof(physical->'audits') IS DISTINCT FROM 'array'
  OR jsonb_typeof(manifest->'consumed_audit_ids') IS DISTINCT FROM 'array'
  OR jsonb_array_length(physical->'audits')<>jsonb_array_length(manifest->'consumed_audit_ids')
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(physical->'audits') a
   WHERE NOT (manifest->'consumed_audit_ids') ? (a->'row'->>'id'))
  OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_audit_ids') identifier GROUP BY identifier HAVING count(*)<>1) THEN
   RAISE EXCEPTION 'resource mandatory audit was omitted' USING ERRCODE='42501';END IF;
 IF jsonb_typeof(manifest->'consumed_object_folds') IS DISTINCT FROM 'array'
  OR jsonb_typeof(physical->'outboxes') IS DISTINCT FROM 'array'
  OR jsonb_array_length(manifest->'consumed_object_folds')<>jsonb_array_length(physical->'outboxes')
  OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_object_folds') n
   WHERE n::integer<1 OR n::integer>jsonb_array_length(physical->'outboxes'))
  OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_object_folds') n GROUP BY n HAVING count(*)<>1) THEN
   RAISE EXCEPTION 'resource mandatory journal fold was omitted' USING ERRCODE='42501';END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_resource_fold_body_v2(p_event_type text,p_payload jsonb,p_created_at timestamptz)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;item jsonb;expected jsonb;row_value jsonb;image jsonb;invoker oid;
 ordinal integer;write_ordinal integer;selected integer:=0;outboxes jsonb;fold_images jsonb;outbox_ordinals jsonb;requires_update boolean:=true;
BEGIN
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NULL THEN RETURN false;END IF;
 IF manifest->'intent'->>'kind'='object' THEN
  outboxes:=manifest#>'{object_physical,outboxes}';fold_images:=manifest#>'{object_fold,images}';
  outbox_ordinals:=manifest->'object_outbox_write_ordinals';
 ELSIF manifest->'intent'->>'kind'='crud' THEN
  PERFORM kaname._authority_crud_manifest_domain_v3(manifest);
  outboxes:=manifest#>'{registration_physical,outboxes}';fold_images:=manifest#>'{registration_physical,fold_images}';
  outbox_ordinals:=manifest->'registration_outbox_write_ordinals';
 ELSIF coalesce(manifest->'intent'->>'Action','') IN ('1','2','3','4') THEN
  outboxes:=manifest#>'{registration_physical,outboxes}';fold_images:=manifest#>'{registration_physical,fold_images}';
  outbox_ordinals:=manifest->'registration_outbox_write_ordinals';
 ELSE RAISE EXCEPTION 'resource fold intent unsupported' USING ERRCODE='42501';END IF;
 IF jsonb_typeof(outboxes) IS DISTINCT FROM 'array' OR jsonb_typeof(fold_images) IS DISTINCT FROM 'array'
 OR jsonb_typeof(outbox_ordinals) IS DISTINCT FROM 'array'
 OR jsonb_typeof(manifest->'consumed_object_folds') IS DISTINCT FROM 'array'
 OR jsonb_array_length(outboxes)>100000 OR jsonb_array_length(fold_images)>100000
 OR jsonb_array_length(outbox_ordinals)<>jsonb_array_length(outboxes) THEN
  RAISE EXCEPTION 'resource fold private program unavailable' USING ERRCODE='42501';END IF;
 expected:=jsonb_build_object('event_type',p_event_type,'payload',p_payload,'created_at',p_created_at);
 ordinal:=0;
 FOR item IN SELECT value FROM jsonb_array_elements(outboxes) LOOP
  ordinal:=ordinal+1;
  IF item->'command' IS DISTINCT FROM manifest->'object_command'
  OR item->'row' IS DISTINCT FROM expected OR (manifest->'consumed_object_folds') @> jsonb_build_array(ordinal) THEN CONTINUE;END IF;
  write_ordinal:=(outbox_ordinals->>(ordinal-1))::integer;
  IF write_ordinal IS NULL OR write_ordinal<1 OR write_ordinal>jsonb_array_length(manifest->'writes') THEN
   RAISE EXCEPTION 'resource fold outbox linkage invalid' USING ERRCODE='42501';END IF;
  -- BEFORE INSERT сопоставил exact image, AFTER ROW подтвердил actual INSERT.
  -- Только обе отметки разрешают fold. Операторный journal trigger идёт
  -- после row triggers; попытка ON CONFLICT DO NOTHING не даёт этого права.
  IF NOT (manifest->'consumed_outbox_writes') @> jsonb_build_array(write_ordinal)
  OR NOT (manifest->'consumed_required_writes') @> jsonb_build_array(write_ordinal) THEN CONTINUE;END IF;
  IF selected=0 THEN selected:=ordinal;END IF;
 END LOOP;
 IF selected=0 THEN RAISE EXCEPTION 'resource fold without matching inserted journal' USING ERRCODE='42501';END IF;
 IF manifest->'intent'->>'kind' IS DISTINCT FROM 'object' THEN
  IF jsonb_typeof(outboxes->(selected-1)->'requires_update_acl') IS DISTINCT FROM 'boolean' THEN
   RAISE EXCEPTION 'registration fold row-lock ACL proof missing' USING ERRCODE='42501';END IF;
  requires_update:=(outboxes->(selected-1)->>'requires_update_acl')::boolean;
 END IF;
 invoker:=(manifest->>'invoker_oid')::oid;
 IF manifest->'intent'->>'Action'='2' THEN
  PERFORM kaname._authority_resource_unregistration_operation_acl_v2(manifest#>'{registration_body,acl}',invoker,
   jsonb_build_object('steps',jsonb_build_array(manifest#>'{registration_program,commands}'->((manifest->>'object_command')::integer-1))));
 END IF;
 FOR image IN SELECT value FROM jsonb_array_elements(fold_images) LOOP
  IF (image->>'outbox')::integer IS DISTINCT FROM selected THEN CONTINUE;END IF;
  IF image->>'table' IS DISTINCT FROM 'relation_fact' OR image->>'operation' NOT IN ('INSERT','UPDATE','DELETE') THEN
   RAISE EXCEPTION 'invalid resource folded physical action' USING ERRCODE='42501';END IF;
  -- INSERT исполняет тот же ON CONFLICT UPDATE, поэтому UPDATE image ниже
  -- является его проверяемым исходом, а не второй независимой командой.
  IF image->>'operation'='UPDATE' THEN CONTINUE;END IF;
  IF image->>'operation'='INSERT' THEN
   IF manifest->'intent'->>'Action'='2' THEN
    RAISE EXCEPTION 'cleanup cannot fold a fact write' USING ERRCODE='42501';END IF;
   IF NOT has_table_privilege(invoker,'kaname.relation_fact','SELECT')
   OR NOT has_table_privilege(invoker,'kaname.relation_fact','INSERT')
   OR NOT has_table_privilege(invoker,'kaname.relation_fact','UPDATE') THEN
    RAISE EXCEPTION 'resource fold requires caller fact upsert ACL' USING ERRCODE='42501';END IF;
   row_value:=image->'new';
   INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject,source_version,created_at,condition_name,condition_params)
   VALUES(row_value->>'object_type',row_value->>'object_id',row_value->>'relation',row_value->>'subject',
    (row_value->>'source_version')::timestamptz,(row_value->>'created_at')::timestamptz,
    row_value->>'condition_name',row_value->'condition_params')
   ON CONFLICT(object_type,object_id,relation,subject) DO UPDATE
    SET source_version=EXCLUDED.source_version,condition_name=EXCLUDED.condition_name
    WHERE relation_fact.source_version<EXCLUDED.source_version;
  ELSE
   IF manifest->'intent'->>'Action' IS DISTINCT FROM '2' THEN
    IF NOT has_table_privilege(invoker,'kaname.relation_fact','SELECT')
    OR NOT has_table_privilege(invoker,'kaname.relation_fact','DELETE')
    OR (requires_update AND NOT has_any_column_privilege(invoker,'kaname.relation_fact','UPDATE')) THEN
     RAISE EXCEPTION 'resource fold requires caller fact delete ACL' USING ERRCODE='42501';END IF;
   END IF;
   row_value:=image->'old';
   DELETE FROM ONLY kaname.relation_fact WHERE object_type=row_value->>'object_type' AND object_id=row_value->>'object_id'
    AND relation=row_value->>'relation' AND subject=row_value->>'subject';
  END IF;
 END LOOP;
 UPDATE pg_temp.kaname_authority_resource_manifest SET consumed_object_folds=array_append(consumed_object_folds,selected);
 RETURN true;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_resource_prewait_v2(p_envelope jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;prepared record;
BEGIN
 IF p_rows IS NULL OR p_rows<1 OR p_rows>100000 OR p_reads IS NULL OR p_reads<1 OR p_reads>4096
 OR jsonb_typeof(p_envelope) IS DISTINCT FROM 'object' OR octet_length(p_envelope::text)>67108864 THEN
  RAISE EXCEPTION 'resource prewait input budget exceeded' USING ERRCODE='54000';END IF;
 IF p_envelope->'abi' IS DISTINCT FROM '2'::jsonb OR jsonb_typeof(p_envelope->'intent') IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'resource prewait ABI mismatch' USING ERRCODE='42501';END IF;
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
 OR proof->>'purpose' IS DISTINCT FROM 'participant' OR proof->>'consumer_abi' IS DISTINCT FROM '2'
 OR proof->>'consumer_finalized' IS DISTINCT FROM 'false'
 OR proof->>'consumer_profile' NOT IN ('resource_pending','resource_source_pending')
 OR current_setting('transaction_isolation')<>'read committed'
 OR to_regclass('pg_temp.kaname_authority_resource_manifest') IS NOT NULL THEN
  RAISE EXCEPTION 'resource prewait requires fresh typed participant' USING ERRCODE='42501';END IF;
 IF p_envelope->'intent'->>'kind'='crud' THEN
  IF p_envelope->'intent' ? 'Action'
  OR proof->>'consumer_profile' IS DISTINCT FROM 'resource_source_pending'
  OR proof->>'writer_contract' IS DISTINCT FROM '2' THEN
   RAISE EXCEPTION 'CRUD requires exact full source participant' USING ERRCODE='42501';END IF;
  SELECT * INTO STRICT prepared FROM kaname._authority_resource_crud_prepare_v3(p_envelope,p_rows,p_reads);
 ELSIF p_envelope->'intent' ? 'kind' THEN
  IF p_envelope->'intent'->>'kind' IS DISTINCT FROM 'object'
  OR p_envelope->'intent' ? 'Action'
  OR proof->>'consumer_profile' IS DISTINCT FROM 'resource_pending' THEN
   RAISE EXCEPTION 'object route requires exact pending object intent' USING ERRCODE='42501';END IF;
  SELECT * INTO STRICT prepared FROM kaname._authority_resource_object_prepare_v2(p_envelope,p_rows,p_reads);
 ELSE
  -- The closed family dispatcher checks Action and delegates to the complete
  -- direct, withdrawal or refusal compiler. Unknown intents never fall back.
  SELECT * INTO STRICT prepared FROM kaname._authority_resource_registration_prepare_v2(p_envelope,p_rows,p_reads);
 END IF;
 IF prepared.logical_rows IS NULL OR prepared.logical_rows<0 OR prepared.logical_rows>p_rows
 OR prepared.logical_reads IS NULL OR prepared.logical_reads<0 OR prepared.logical_reads>p_reads THEN
  RAISE EXCEPTION 'resource compiler exceeded shared budget' USING ERRCODE='54000';END IF;
 RETURN QUERY SELECT prepared.logical_rows::integer,prepared.logical_reads::integer;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Чистые domain/FK images по закрытому actual command plan. Здесь нет
-- чтений, nextval или блокировок: clock подставляется только в известные поля.
-- Fold, audit, journal и quota images компилируются отдельными закрытыми слоями.
CREATE FUNCTION kaname._authority_crud_image_v3(p_command integer,p_table text,p_op text,p_old jsonb,p_new jsonb,p_required boolean DEFAULT true)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF p_command IS NULL OR p_command<1 OR p_command>100000 OR p_table IS NULL
 OR p_op IS NULL OR p_op NOT IN ('INSERT','UPDATE','DELETE') OR p_required IS NULL
 OR (p_op='INSERT' AND (p_old IS NOT NULL AND p_old<>'null'::jsonb OR jsonb_typeof(p_new) IS DISTINCT FROM 'object'))
 OR (p_op='DELETE' AND (p_new IS NOT NULL AND p_new<>'null'::jsonb OR jsonb_typeof(p_old) IS DISTINCT FROM 'object'))
 OR (p_op='UPDATE' AND (jsonb_typeof(p_old) IS DISTINCT FROM 'object' OR jsonb_typeof(p_new) IS DISTINCT FROM 'object')) THEN
  RAISE EXCEPTION 'invalid closed CRUD image' USING ERRCODE='42501';END IF;
 RETURN jsonb_build_array(jsonb_build_object('command',p_command,'table',p_table,'operation',p_op,
  'old',p_old,'new',p_new,'required',p_required));
END $$;

CREATE FUNCTION kaname._authority_crud_domain_images_v3(p_intent jsonb,p_sources jsonb,p_program jsonb,p_at timestamptz)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE descriptor jsonb;step jsonb;request jsonb;entry jsonb;row_value jsonb;old_row jsonb;new_row jsonb;
 images jsonb:='[]'::jsonb;kind text;table_name text;target_id text;actor_id text;command_no integer:=0;
 binding_id text;binding_row jsonb;subject jsonb;tuple_value jsonb;member jsonb;table_rows jsonb;
BEGIN
 descriptor:=kaname._authority_crud_intent_v3(p_intent);
 IF p_at IS NULL OR p_sources->'descriptor' IS DISTINCT FROM descriptor
 OR p_program IS DISTINCT FROM kaname._authority_crud_command_plan_v3(p_intent,p_sources) THEN
  RAISE EXCEPTION 'CRUD domain plan not server derived' USING ERRCODE='42501';END IF;
 target_id:=descriptor->>'id';actor_id:=split_part(descriptor->>'actor',':',2);
 FOR step IN SELECT value FROM jsonb_array_elements(p_program->'commands') LOOP
  command_no:=command_no+1;kind:=step->>'kind';request:=step->'request';
  IF kind IN ('account.insert','project.insert','service_account.insert') THEN
   table_name:=CASE kind WHEN 'account.insert' THEN 'accounts' WHEN 'project.insert' THEN 'projects' ELSE 'service_accounts' END;
   new_row:=jsonb_build_object('id',request->>'ID','name',request->>'Name','description',request->>'Description',
    'labels',coalesce(nullif(request->'Labels','null'::jsonb),'{}'::jsonb),'created_at',p_at);
   IF table_name='accounts' THEN new_row:=new_row||jsonb_build_object('owner_user_id',request->>'OwnerUserID');
   ELSE new_row:=new_row||jsonb_build_object('account_id',request->>'AccountID');END IF;
   IF table_name='service_accounts' THEN
    new_row:=new_row||jsonb_build_object('enabled',true,'created_by_type',nullif(request#>>'{CreatedBy,Type}',''),
     'created_by_id',nullif(request#>>'{CreatedBy,ID}',''));
   END IF;
   images:=images||kaname._authority_crud_image_v3(command_no,table_name,'INSERT',NULL,new_row);
  ELSIF kind='binding.insert' THEN
   binding_id:=request#>>'{}';
   IF descriptor->>'command'<>'account.create' OR binding_id IS DISTINCT FROM p_intent#>>'{input,OwnerBindingID}' THEN
    RAISE EXCEPTION 'CRUD binding creation outside account owner step' USING ERRCODE='42501';END IF;
   binding_row:=jsonb_build_object('id',binding_id,'subject_type','user','subject_id',p_intent#>>'{input,Account,OwnerUserID}',
    'role_id','rol72122ce96bfec66e2','resource_type','account','resource_id',target_id,'created_at',p_at,
    'status','ACTIVE','expires_at',NULL,'granted_by_user_id',actor_id,'revoked_at',NULL,'revoked_by_user_id',NULL,
    'scope',2,'deletion_protection',true,'labels','{}'::jsonb,'target',jsonb_build_object('allInScope',true),
    'target_digest','all','granted_relation','','is_system',false,'delegation_id',NULL,
    'revocation_reason',NULL,'narrowed_at',NULL,'grant_capability_version',0);
   images:=images||kaname._authority_crud_image_v3(command_no,'access_bindings','INSERT',NULL,binding_row);
  ELSIF kind='binding.subjects' THEN
   IF binding_row IS NULL OR request->>'ID' IS DISTINCT FROM binding_row->>'id' THEN
    RAISE EXCEPTION 'CRUD subject carrier absent from prior command' USING ERRCODE='42501';END IF;
   FOR subject IN SELECT value FROM jsonb_array_elements(request->'Subjects') LOOP
    new_row:=jsonb_build_object('binding_id',request->>'ID','subject_type',subject->>'Type','subject_id',subject->>'ID',
     'resource_type','account','resource_id',target_id,'ordinal',0);
    images:=images||kaname._authority_crud_image_v3(command_no,'access_binding_subjects','INSERT',NULL,new_row);
   END LOOP;
  ELSIF kind='binding.ledger' THEN
   IF binding_row IS NULL OR request->>'ID' IS DISTINCT FROM binding_row->>'id' THEN
    RAISE EXCEPTION 'CRUD ledger carrier absent from prior command' USING ERRCODE='42501';END IF;
   FOR tuple_value IN SELECT value FROM jsonb_array_elements(request->'Tuples') LOOP
    new_row:=jsonb_build_object('binding_id',request->>'ID','relation',tuple_value->>'Relation',
     'object',tuple_value->>'Object','fga_user',tuple_value->>'User','source','binding','member_object_type','','member_object_id','');
    images:=images||kaname._authority_crud_image_v3(command_no,'access_binding_emitted_tuples','INSERT',NULL,new_row);
   END LOOP;
  ELSIF kind='binding.delete' THEN
   binding_id:=request#>>'{}';old_row:=NULL;
   SELECT value INTO old_row FROM jsonb_array_elements(p_sources->'scope_bindings') WHERE value->>'id'=binding_id;
   IF old_row IS NULL THEN RAISE EXCEPTION 'CRUD binding OLD omitted' USING ERRCODE='42501';END IF;
   images:=images||kaname._authority_crud_image_v3(command_no,'access_bindings','DELETE',old_row,NULL);
   FOREACH table_name IN ARRAY ARRAY['access_binding_subjects','access_binding_target_members','access_binding_emitted_tuples'] LOOP
    table_rows:=p_sources->'tables'->table_name;
    IF jsonb_typeof(table_rows) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'CRUD binding cascade missing' USING ERRCODE='42501';END IF;
    FOR entry IN SELECT value FROM jsonb_array_elements(table_rows) WHERE value->'row'->>'binding_id'=binding_id LOOP
     images:=images||kaname._authority_crud_image_v3(command_no,table_name,'DELETE',entry->'row',NULL);
    END LOOP;
   END LOOP;
  ELSIF kind IN ('account.delete','project.delete','service_account.delete','role.delete') THEN
   table_name:=CASE kind WHEN 'account.delete' THEN 'accounts' WHEN 'project.delete' THEN 'projects'
    WHEN 'service_account.delete' THEN 'service_accounts' ELSE 'roles' END;
   old_row:=p_sources#>'{primary,row}';
   IF old_row->>'id' IS DISTINCT FROM request#>>'{}' OR jsonb_typeof(old_row) IS DISTINCT FROM 'object' THEN
    RAISE EXCEPTION 'CRUD primary OLD omitted' USING ERRCODE='42501';END IF;
   images:=images||kaname._authority_crud_image_v3(command_no,table_name,'DELETE',old_row,NULL);
   IF kind='account.delete' THEN
    IF jsonb_typeof(p_sources#>'{tables,memberships}') IS DISTINCT FROM 'array'
    OR jsonb_typeof(p_sources#>'{tables,users}') IS DISTINCT FROM 'array' THEN
     RAISE EXCEPTION 'CRUD account cascade omitted' USING ERRCODE='42501';END IF;
    FOR entry IN SELECT value FROM jsonb_array_elements(p_sources#>'{tables,memberships}') LOOP
     images:=images||kaname._authority_crud_image_v3(command_no,'memberships','DELETE',entry->'row',NULL);
    END LOOP;
    FOR entry IN SELECT value FROM jsonb_array_elements(p_sources#>'{tables,users}') LOOP
     old_row:=entry->'row';new_row:=old_row||jsonb_build_object('account_id',NULL);
     images:=images||kaname._authority_crud_image_v3(command_no,'users','UPDATE',old_row,new_row);
    END LOOP;
   ELSIF kind='role.delete' THEN
    FOREACH table_name IN ARRAY ARRAY['access_binding_target_members','role_rule_selectors','role_selector_verbs_pending',
     'role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule','role_grant_orphan','role_selector_prune'] LOOP
     table_rows:=p_sources->'tables'->table_name;
     IF jsonb_typeof(table_rows) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'CRUD role cascade omitted' USING ERRCODE='42501';END IF;
     FOR entry IN SELECT value FROM jsonb_array_elements(table_rows) LOOP
      images:=images||kaname._authority_crud_image_v3(command_no,table_name,'DELETE',entry->'row',NULL);
     END LOOP;
    END LOOP;
   END IF;
  ELSIF kind NOT IN ('audit','binding.audit','reconcile','fga.tuple.write','fga.tuple.delete') THEN
   RAISE EXCEPTION 'unclassified CRUD domain command' USING ERRCODE='42501';
  END IF;
  IF jsonb_array_length(images)>100000 THEN RAISE EXCEPTION 'CRUD domain image budget exceeded' USING ERRCODE='54000';END IF;
 END LOOP;
 RETURN images;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Закрытый словарь семи CRUD. Никакой caller image не является разрешением DML.
CREATE FUNCTION kaname._authority_crud_intent_v3(p_intent jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE command text; actor text; input jsonb; object_input jsonb; target_id text;
 target_table text; target_type text; owner_account text; global_mode boolean:=true;
BEGIN
 IF jsonb_typeof(p_intent) IS DISTINCT FROM 'object'
 OR p_intent->>'kind' IS DISTINCT FROM 'crud'
 OR p_intent-'kind'-'command'-'actor'-'input'<>'{}'::jsonb
 OR jsonb_typeof(p_intent->'command') IS DISTINCT FROM 'string'
 OR jsonb_typeof(p_intent->'actor') IS DISTINCT FROM 'string'
 OR octet_length(p_intent::text)>67108864 THEN
  RAISE EXCEPTION 'invalid closed CRUD intent' USING ERRCODE='42501';END IF;
 command:=p_intent->>'command';actor:=p_intent->>'actor';input:=p_intent->'input';
 IF split_part(actor,':',1) NOT IN ('user','service_account')
 OR split_part(actor,':',2) IN ('','*') OR array_length(string_to_array(actor,':'),1)<>2
 OR btrim(actor)<>actor THEN RAISE EXCEPTION 'invalid CRUD typed actor' USING ERRCODE='42501';END IF;
 CASE command
 WHEN 'account.create' THEN
  IF jsonb_typeof(input) IS DISTINCT FROM 'object'
   OR input-'Account'-'DefaultProjectID'-'OwnerBindingID'-'IDSource'<>'{}'::jsonb
   OR jsonb_typeof(input->'Account') IS DISTINCT FROM 'object'
   OR coalesce(input->>'IDSource','') NOT IN ('generated','supplied')
   OR coalesce(input->>'DefaultProjectID','')='' OR coalesce(input->>'OwnerBindingID','')=''
   OR actor IS DISTINCT FROM 'user:'||(input#>>'{Account,OwnerUserID}') THEN
   RAISE EXCEPTION 'invalid account creation identity' USING ERRCODE='42501';END IF;
  object_input:=input->'Account';target_table:='accounts';target_type:='account';
 WHEN 'project.create' THEN
  object_input:=input;target_table:='projects';target_type:='project';global_mode:=false;
  owner_account:=input->>'AccountID';
 WHEN 'service_account.create' THEN
  object_input:=input;target_table:='service_accounts';target_type:='iam_service_account';
  owner_account:=input->>'AccountID';
  -- INSERT сервиса использует DEFAULT enabled=true независимо от Go zero-value.
   IF jsonb_typeof(input->'Enabled') IS DISTINCT FROM 'boolean'
   OR input#>>'{CreatedBy,Type}'||':'||(input#>>'{CreatedBy,ID}') IS DISTINCT FROM actor THEN
   RAISE EXCEPTION 'invalid service account creator' USING ERRCODE='42501';END IF;
 WHEN 'account.delete' THEN target_table:='accounts';target_type:='account';
 WHEN 'project.delete' THEN target_table:='projects';target_type:='project';
 WHEN 'service_account.delete' THEN target_table:='service_accounts';target_type:='iam_service_account';
 WHEN 'role.delete' THEN target_table:='roles';target_type:='iam_role';
 ELSE RAISE EXCEPTION 'unsupported CRUD command' USING ERRCODE='42501';
 END CASE;
 IF command LIKE '%.create' THEN
  IF jsonb_typeof(object_input) IS DISTINCT FROM 'object'
   OR jsonb_typeof(object_input->'ID') IS DISTINCT FROM 'string'
   OR jsonb_typeof(object_input->'Name') IS DISTINCT FROM 'string'
   OR jsonb_typeof(object_input->'Description') IS DISTINCT FROM 'string'
   OR jsonb_typeof(object_input->'Labels') IS NULL OR jsonb_typeof(object_input->'Labels') NOT IN ('object','null')
   OR (object_input-(CASE command
    WHEN 'account.create' THEN ARRAY['ID','Name','Description','Labels','OwnerUserID','CreatedAt']
    WHEN 'project.create' THEN ARRAY['ID','AccountID','Name','Description','Labels','CreatedAt']
    ELSE ARRAY['ID','AccountID','Name','Description','Labels','Enabled','CreatedAt','CreatedBy'] END))<>'{}'::jsonb THEN
   RAISE EXCEPTION 'invalid CRUD new object' USING ERRCODE='42501';END IF;
  target_id:=object_input->>'ID';
 ELSE
  IF jsonb_typeof(input) IS DISTINCT FROM 'string' THEN
   RAISE EXCEPTION 'CRUD deletion requires exact ID' USING ERRCODE='42501';END IF;
  target_id:=input#>>'{}';
 END IF;
 IF coalesce(target_id,'')='' OR btrim(target_id)<>target_id
 OR (command IN ('project.create','service_account.create') AND coalesce(owner_account,'')='') THEN
  RAISE EXCEPTION 'CRUD target or owner missing' USING ERRCODE='42501';END IF;
 RETURN jsonb_build_object('command',command,'actor',actor,'table',target_table,
  'model_type',target_type,'id',target_id,'account',owner_account,'global',global_mode);
END $$;

CREATE FUNCTION kaname._authority_crud_manifest_domain_v3(p_manifest jsonb) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE descriptor jsonb; proof jsonb; allowed text[];
BEGIN
 descriptor:=kaname._authority_crud_intent_v3(p_manifest->'intent');
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'writer_contract' IS DISTINCT FROM '2'
 OR proof->>'kind' IS DISTINCT FROM 'resource' OR proof->>'purpose' IS DISTINCT FROM 'participant'
 OR proof->>'consumer_abi' IS DISTINCT FROM '2'
 OR proof->>'consumer_profile' IS DISTINCT FROM 'resource_source_pending'
 OR (descriptor->>'global'='true' AND proof->>'mode' IS DISTINCT FROM 'global')
 OR (descriptor->>'global'='false' AND (proof->>'mode' IS DISTINCT FROM 'accounts'
   OR proof->'accounts' IS DISTINCT FROM jsonb_build_array(descriptor->>'account')))
 OR p_manifest#>>'{registration_certificate,command}' IS DISTINCT FROM descriptor->>'command'
 OR p_manifest#>'{registration_certificate,intent}' IS DISTINCT FROM p_manifest->'intent' THEN
  RAISE EXCEPTION 'CRUD manifest has no exact full participant domain' USING ERRCODE='42501';END IF;
 CASE descriptor->>'command'
 WHEN 'account.create' THEN allowed:=ARRAY['accounts','projects','access_bindings',
  'access_binding_subjects','access_binding_emitted_tuples','relation_fact','fga_outbox'];
 WHEN 'account.delete' THEN allowed:=ARRAY['accounts','users','memberships','access_bindings',
  'access_binding_subjects','access_binding_target_members','access_binding_emitted_tuples','relation_fact','fga_outbox'];
 WHEN 'project.create' THEN allowed:=ARRAY['projects','relation_fact','fga_outbox'];
 WHEN 'project.delete' THEN allowed:=ARRAY['projects','access_bindings','access_binding_subjects',
  'access_binding_target_members','access_binding_emitted_tuples','relation_fact','fga_outbox'];
 WHEN 'service_account.create','service_account.delete' THEN allowed:=ARRAY['service_accounts','relation_fact','fga_outbox'];
 WHEN 'role.delete' THEN allowed:=ARRAY['roles','access_binding_target_members','access_binding_emitted_tuples','role_rule_selectors','role_selector_verbs_pending',
  'role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule','relation_fact','fga_outbox'];
 ELSE RAISE EXCEPTION 'CRUD write domain missing' USING ERRCODE='42501';
 END CASE;
 IF jsonb_typeof(p_manifest->'writes') IS DISTINCT FROM 'array'
 OR jsonb_array_length(p_manifest->'writes')>100000
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(p_manifest->'writes') w
  WHERE NOT coalesce(w->>'table','')=ANY(allowed)
   OR coalesce(w->>'operation','') NOT IN ('INSERT','UPDATE','DELETE')) THEN
  RAISE EXCEPTION 'CRUD write escapes closed family' USING ERRCODE='42501';END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Идентификатор FGA outbox — часть exact CRUD эффекта, хотя старый Resource
-- row-image codec намеренно исключает surrogate id для остальных программ.
CREATE FUNCTION kaname._authority_crud_fga_rows_v3(p_tuples jsonb,p_kind text,p_ids jsonb,p_command integer,p_at timestamptz)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE grouped record;payload jsonb;result jsonb:='[]'::jsonb;ordinal integer:=0;identifier bigint;
BEGIN
 IF jsonb_typeof(p_tuples) IS DISTINCT FROM 'array' OR jsonb_typeof(p_ids) IS DISTINCT FROM 'array'
 OR jsonb_array_length(p_tuples)>100000 OR jsonb_array_length(p_ids)>100000
 OR p_kind IS NULL OR p_kind NOT IN ('fga.tuple.write','fga.tuple.delete')
 OR p_command IS NULL OR p_command<1 OR p_at IS NULL THEN
  RAISE EXCEPTION 'invalid CRUD journal command' USING ERRCODE='42501';END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(p_tuples) t
  WHERE jsonb_typeof(t) IS DISTINCT FROM 'object' OR t-'User'-'Relation'-'Object'<>'{}'::jsonb
   OR coalesce(t->>'User','')='' OR coalesce(t->>'Relation','')='' OR coalesce(t->>'Object','')='') THEN
  RAISE EXCEPTION 'invalid CRUD structural tuple' USING ERRCODE='42501';END IF;
 -- Тот же dedup и порядок, что groupByGrant actual Go emitter: object,user;
 -- relations внутри группы сортируются, повтор целого tuple исчезает.
 FOR grouped IN
  SELECT object_value,user_value,jsonb_agg(relation_value ORDER BY relation_value COLLATE "C") relations
  FROM (SELECT DISTINCT t->>'Object' object_value,t->>'User' user_value,t->>'Relation' relation_value
   FROM jsonb_array_elements(p_tuples) t) x
  GROUP BY object_value,user_value ORDER BY object_value COLLATE "C",user_value COLLATE "C"
 LOOP
  ordinal:=ordinal+1;identifier:=(p_ids->>(ordinal-1))::bigint;
  IF identifier IS NULL OR identifier<=0
   OR (ordinal>1 AND identifier<=(p_ids->>(ordinal-2))::bigint) THEN
   RAISE EXCEPTION 'CRUD reserved journal IDs differ from grouped payloads' USING ERRCODE='42501';END IF;
  payload:=jsonb_build_object('user',grouped.user_value,'object',grouped.object_value);
  IF jsonb_array_length(grouped.relations)=1 THEN
   payload:=payload||jsonb_build_object('relation',grouped.relations->0);
  ELSE
   payload:=payload||jsonb_build_object('relations',grouped.relations);
   IF p_kind='fga.tuple.write' THEN payload:=payload||jsonb_build_object('relation',grouped.relations->0);END IF;
  END IF;
  result:=result||jsonb_build_array(jsonb_build_object('command',p_command,'id',identifier,
   'requires_update_acl',true,'row',jsonb_build_object('event_type',p_kind,'payload',payload,'created_at',p_at)));
 END LOOP;
 IF ordinal<>jsonb_array_length(p_ids) THEN
  RAISE EXCEPTION 'CRUD reserved journal count differs from actual groups' USING ERRCODE='42501';END IF;
 RETURN result;
END $$;

CREATE FUNCTION kaname.authority_crud_fga_id_guard_v3() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;expected jsonb;actual jsonb;matches integer;
BEGIN
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NULL OR manifest->'intent'->>'kind' IS DISTINCT FROM 'crud' THEN RETURN NEW;END IF;
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME<>'fga_outbox' OR TG_OP<>'INSERT'
 OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW'
 OR manifest->>'registration_program_claimed' IS DISTINCT FROM 'true' THEN
  RAISE EXCEPTION 'invalid CRUD FGA exact ID guard' USING ERRCODE='42501';END IF;
 actual:=jsonb_build_object('event_type',NEW.event_type,'payload',NEW.payload,'created_at',NEW.created_at);
 SELECT count(*)::integer INTO matches FROM jsonb_array_elements(manifest#>'{registration_physical,outboxes}') entry
 WHERE entry->'command'=manifest->'object_command' AND entry->'id'=to_jsonb(NEW.id) AND entry->'row'=actual;
 IF matches<>1 OR coalesce(manifest#>'{registration_body,consumed_fga_ids}','[]'::jsonb) @> jsonb_build_array(NEW.id) THEN
  RAISE EXCEPTION 'CRUD FGA ID does not belong to exact current command' USING ERRCODE='42501';END IF;
 -- Общий INSERT guard уже поддерживает один namespace с direct runtime INSERT.
 -- Здесь только проверка: не добавляем ожидание после final clock.
 PERFORM kaname._authority_resource_preheld_key_v2(1262569305,NEW.id::text,true);
 RETURN NEW;
END $$;

CREATE FUNCTION kaname.authority_crud_fga_id_applied_v3() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;matches integer;
BEGIN
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NULL OR manifest->'intent'->>'kind' IS DISTINCT FROM 'crud' THEN RETURN NULL;END IF;
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME<>'fga_outbox' OR TG_OP<>'INSERT'
 OR TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' THEN
  RAISE EXCEPTION 'invalid CRUD FGA applied ID guard' USING ERRCODE='42501';END IF;
 SELECT count(*)::integer INTO matches FROM jsonb_array_elements(manifest#>'{registration_physical,outboxes}') entry
 WHERE entry->'command'=manifest->'object_command' AND entry->'id'=to_jsonb(NEW.id)
 AND entry->'row'=jsonb_build_object('event_type',NEW.event_type,'payload',NEW.payload,'created_at',NEW.created_at);
 IF matches<>1 OR coalesce(manifest#>'{registration_body,consumed_fga_ids}','[]'::jsonb) @> jsonb_build_array(NEW.id) THEN
  RAISE EXCEPTION 'CRUD FGA exact ID consumption mismatch' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_authority_resource_manifest
 SET registration_body=jsonb_set(registration_body,'{consumed_fga_ids}',
  coalesce(registration_body->'consumed_fga_ids','[]'::jsonb)||jsonb_build_array(NEW.id));
 RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Fold capture использует exact tuple coordinates actual command plan.
-- Держатели чужих binding сохраняются даже вне удаляемой области: только
-- server-side EXISTS по persisted ledger определяет полный holder graph.
CREATE FUNCTION kaname._authority_crud_fold_capture_v3(p_program jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE tuples jsonb;tables jsonb:='{}';rows_value jsonb;query_text text;entry record;
 used_rows integer:=0;used_reads integer:=0;binding_ids text[];bindings jsonb:='{}';ledger jsonb:='{}';row_value jsonb;
BEGIN
 IF jsonb_typeof(p_program->'commands') IS DISTINCT FROM 'array' OR p_rows IS NULL OR p_rows<0 OR p_rows>100000
 OR p_reads IS NULL OR p_reads<0 OR p_reads>4096 THEN
  RAISE EXCEPTION 'invalid CRUD fold capture' USING ERRCODE='42501';END IF;
 SELECT coalesce(jsonb_agg(coordinates.row_value ORDER BY coordinates.row_value::text COLLATE "C"),'[]'::jsonb) INTO tuples FROM (
  SELECT DISTINCT t.value row_value FROM jsonb_array_elements(p_program->'commands') c
  CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN c->>'kind' IN ('fga.tuple.write','fga.tuple.delete')
   THEN c->'request' ELSE '[]'::jsonb END) t
 ) coordinates;
 IF jsonb_array_length(tuples)>100000 THEN RAISE EXCEPTION 'CRUD fold coordinate budget exceeded' USING ERRCODE='54000';END IF;
 IF tuples='[]'::jsonb THEN
  RETURN jsonb_build_object('tables',jsonb_build_object('relation_fact','[]'::jsonb,'access_binding_emitted_tuples','[]'::jsonb,
   'resource_registration_pointer','[]'::jsonb,'resource_registration_retirement','[]'::jsonb,
   'cluster_admin_grants','[]'::jsonb,'access_bindings','[]'::jsonb),'tuples',tuples,'bindings',bindings,
   'ledger',ledger,'logical_rows',0,'logical_reads',0);
 END IF;
 FOR entry IN SELECT * FROM (VALUES
  ('relation_fact','t.object_type||'':''||t.object_id=q->>''Object'' AND t.relation=q->>''Relation'' AND
   (t.subject=q->>''User'' OR (q->>''User''=''user:*'' AND t.subject=''system_class:authenticated''))'),
  ('access_binding_emitted_tuples','t.object=q->>''Object'' AND t.relation=q->>''Relation'' AND
   (t.fga_user=q->>''User'' OR (q->>''User''=''user:*'' AND t.fga_user=''system_class:authenticated''))'),
  ('resource_registration_pointer','t.object_type||'':''||t.object_id=q->>''Object'' AND t.relation=q->>''Relation'' AND t.subject=q->>''User'''),
  ('resource_registration_retirement','t.object_type||'':''||t.object_id=q->>''Object'' AND t.relation=q->>''Relation'' AND t.subject=q->>''User'''),
  ('cluster_admin_grants','''cluster:''||t.cluster_id=q->>''Object'' AND q->>''Relation''=''system_admin''
   AND t.subject_type||'':''||t.subject_id=q->>''User''')
 ) selected(table_name,predicate) LOOP
  IF used_reads>=p_reads THEN RAISE EXCEPTION 'CRUD fold read budget exceeded' USING ERRCODE='54000';END IF;
  query_text:=format('SELECT coalesce(jsonb_agg(jsonb_build_object(''row'',row_value,''xmin'',xmin_value,''ctid'',ctid_value)
   ORDER BY row_value::text COLLATE "C"),''[]''::jsonb) FROM
   (SELECT to_jsonb(t) row_value,t.xmin::text xmin_value,t.ctid::text ctid_value FROM ONLY kaname.%I t
    WHERE EXISTS(SELECT 1 FROM jsonb_array_elements($1) q WHERE %s)
    ORDER BY to_jsonb(t)::text COLLATE "C" LIMIT $2) captured',entry.table_name,entry.predicate);
  EXECUTE query_text INTO rows_value USING tuples,p_rows-used_rows+1;
  used_reads:=used_reads+1;used_rows:=used_rows+jsonb_array_length(rows_value);
  IF used_rows>p_rows THEN RAISE EXCEPTION 'CRUD fold row budget exceeded' USING ERRCODE='54000';END IF;
  tables:=tables||jsonb_build_object(entry.table_name,rows_value);
 END LOOP;
 SELECT coalesce(array_agg(DISTINCT e->'row'->>'binding_id'),ARRAY[]::text[]) INTO binding_ids
 FROM jsonb_array_elements(tables->'access_binding_emitted_tuples') e;
 IF used_reads>=p_reads THEN RAISE EXCEPTION 'CRUD fold carrier read budget exceeded' USING ERRCODE='54000';END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('row',captured.row_value,'xmin',captured.xmin_value,'ctid',captured.ctid_value)
  ORDER BY captured.row_value->>'id' COLLATE "C"),'[]'::jsonb) INTO rows_value
 FROM (SELECT to_jsonb(b) row_value,b.xmin::text xmin_value,b.ctid::text ctid_value FROM ONLY kaname.access_bindings b
  WHERE b.id=ANY(binding_ids) ORDER BY b.id COLLATE "C" LIMIT p_rows-used_rows+1) captured;
 used_reads:=used_reads+1;used_rows:=used_rows+jsonb_array_length(rows_value);
 IF used_rows>p_rows THEN RAISE EXCEPTION 'CRUD fold carrier row budget exceeded' USING ERRCODE='54000';END IF;
 tables:=tables||jsonb_build_object('access_bindings',rows_value);
 FOR row_value IN SELECT value->'row' FROM jsonb_array_elements(rows_value) LOOP
  bindings:=bindings||jsonb_build_object(row_value->>'id',row_value);
 END LOOP;
 FOR row_value IN SELECT value->'row' FROM jsonb_array_elements(tables->'access_binding_emitted_tuples') LOOP
  ledger:=ledger||jsonb_build_object(jsonb_build_array(row_value->>'binding_id',row_value->>'member_object_type',
   row_value->>'member_object_id',row_value->>'fga_user',row_value->>'relation',row_value->>'object')::text,row_value);
 END LOOP;
 RETURN jsonb_build_object('tables',tables,'tuples',tuples,'bindings',bindings,'ledger',ledger,
  'logical_rows',used_rows,'logical_reads',used_reads);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Fold после каждого actual FGA шага видит состояние, оставленное именно
-- предыдущими командами. Снятый binding не сохраняется фиктивным holder.
CREATE FUNCTION kaname._authority_crud_fold_images_v3(p_program jsonb,p_domain jsonb,p_outboxes jsonb,p_sources jsonb,
 p_tx_at timestamptz,p_at timestamptz) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE bindings jsonb;ledger jsonb;facts jsonb;pointers jsonb;retirements jsonb;grants jsonb;
 result jsonb;step jsonb;image jsonb;entry record;command_no integer:=0;offset_no integer:=0;
 current_outboxes jsonb;images jsonb:='[]';work integer:=0;binding_id text;row_value jsonb;key_value text;
BEGIN
 IF jsonb_typeof(p_domain) IS DISTINCT FROM 'array' OR jsonb_typeof(p_outboxes) IS DISTINCT FROM 'array'
 OR jsonb_typeof(p_sources->'bindings') IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_sources->'ledger') IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_program->'commands') IS DISTINCT FROM 'array' OR p_tx_at IS NULL OR p_at IS NULL THEN
  RAISE EXCEPTION 'CRUD ordered fold source incomplete' USING ERRCODE='42501';END IF;
 bindings:=p_sources->'bindings';ledger:=p_sources->'ledger';
 SELECT coalesce(jsonb_agg(value->'row'),'[]'::jsonb) INTO facts FROM jsonb_array_elements(p_sources#>'{tables,relation_fact}');
 SELECT coalesce(jsonb_agg(value->'row'),'[]'::jsonb) INTO pointers FROM jsonb_array_elements(p_sources#>'{tables,resource_registration_pointer}');
 SELECT coalesce(jsonb_agg(value->'row'),'[]'::jsonb) INTO retirements FROM jsonb_array_elements(p_sources#>'{tables,resource_registration_retirement}');
 SELECT coalesce(jsonb_agg(value->'row'),'[]'::jsonb) INTO grants FROM jsonb_array_elements(p_sources#>'{tables,cluster_admin_grants}');
 FOR step IN SELECT value FROM jsonb_array_elements(p_program->'commands') LOOP
  command_no:=command_no+1;
  FOR image IN SELECT value FROM jsonb_array_elements(p_domain) WHERE (value->>'command')::integer=command_no LOOP
   IF image->>'table'='access_bindings' THEN
    IF image->>'operation'='DELETE' THEN bindings:=bindings-(image->'old'->>'id');
    ELSE bindings:=bindings||jsonb_build_object(image->'new'->>'id',image->'new');END IF;
   ELSIF image->>'table'='access_binding_emitted_tuples' THEN
    IF image->>'operation'='UPDATE' THEN RAISE EXCEPTION 'CRUD ledger update unsupported' USING ERRCODE='42501';END IF;
    row_value:=CASE WHEN image->>'operation'='DELETE' THEN image->'old' ELSE image->'new' END;
    key_value:=jsonb_build_array(row_value->>'binding_id',row_value->>'member_object_type',row_value->>'member_object_id',
     row_value->>'fga_user',row_value->>'relation',row_value->>'object')::text;
    IF image->>'operation'='DELETE' THEN ledger:=ledger-key_value;
    ELSE ledger:=ledger||jsonb_build_object(key_value,row_value);END IF;
   END IF;
  END LOOP;
  IF step->>'kind' NOT IN ('fga.tuple.write','fga.tuple.delete') THEN CONTINUE;END IF;
  SELECT coalesce(jsonb_agg(value ORDER BY ord),'[]'::jsonb) INTO current_outboxes
  FROM jsonb_array_elements(p_outboxes) WITH ORDINALITY q(value,ord) WHERE (value->>'command')::integer=command_no;
  result:=kaname._authority_resource_object_fold_v2(current_outboxes,facts,bindings,ledger,pointers,retirements,grants,p_tx_at,p_at);
  FOR image IN SELECT value FROM jsonb_array_elements(result->'images') LOOP
   images:=images||jsonb_build_array(jsonb_set(image,'{outbox}',to_jsonb((image->>'outbox')::integer+offset_no)));
  END LOOP;
  SELECT coalesce(jsonb_agg(value ORDER BY key COLLATE "C"),'[]'::jsonb) INTO facts FROM jsonb_each(result->'facts');
  offset_no:=offset_no+jsonb_array_length(current_outboxes);work:=work+(result->>'work')::integer;
  IF work>400000 OR jsonb_array_length(images)>100000 THEN
   RAISE EXCEPTION 'CRUD ordered fold work exceeded' USING ERRCODE='54000';END IF;
 END LOOP;
 IF offset_no<>jsonb_array_length(p_outboxes) THEN RAISE EXCEPTION 'CRUD fold skipped a journal command' USING ERRCODE='42501';END IF;
 RETURN jsonb_build_object('images',images,'work',work);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Индекс только server-captured graph и чистых exact images. Нельзя
-- подставить metadata из caller request вместо захваченной строки источника.
CREATE FUNCTION kaname._authority_crud_graph_index_v3(p_intent jsonb,p_sources jsonb,p_domain jsonb)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE descriptor jsonb;tables jsonb;result jsonb;entry jsonb;image jsonb;row_value jsonb;table_name text;map_name text;
 identifier text;coordinate text;account_id text;prior jsonb;subjects jsonb:='{}';broad jsonb:='{}';objects jsonb:='{}';work integer:=0;
BEGIN
 descriptor:=kaname._authority_crud_intent_v3(p_intent);
 IF p_sources->'descriptor' IS DISTINCT FROM descriptor OR jsonb_typeof(p_domain) IS DISTINCT FROM 'array'
 OR jsonb_typeof(p_sources->'authority_graph') IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'CRUD metadata graph absent' USING ERRCODE='42501';END IF;
 tables:=kaname._authority_crud_merge_tables_v3(p_sources->'tables',p_sources->'authority_graph');
 -- Корень и parent не смешиваются с перечнем FK cascade; они входят
 -- только в metadata index. NEW row добавляется ниже из compiler image.
 IF p_sources#>'{primary,row}'<>'null'::jsonb THEN
  tables:=kaname._authority_crud_merge_tables_v3(tables,jsonb_build_object(descriptor->>'table',jsonb_build_array(p_sources->'primary')));END IF;
 IF p_sources#>'{parent,row}'<>'null'::jsonb THEN
  tables:=kaname._authority_crud_merge_tables_v3(tables,jsonb_build_object('accounts',jsonb_build_array(p_sources->'parent')));END IF;
 result:=jsonb_build_object('descriptor',descriptor,'roles','{}'::jsonb,'projects','{}'::jsonb,
  'groups','{}'::jsonb,'bindings','{}'::jsonb,'accounts','{}'::jsonb,'service_accounts','{}'::jsonb);
 FOREACH table_name IN ARRAY ARRAY['accounts','projects','service_accounts','roles','groups','access_bindings'] LOOP
  map_name:=CASE WHEN table_name='access_bindings' THEN 'bindings' ELSE table_name END;
  FOR row_value IN
   SELECT value->'row' FROM jsonb_array_elements(coalesce(tables->table_name,'[]'::jsonb))
   UNION SELECT value->'old' FROM jsonb_array_elements(p_domain) WHERE value->>'table'=table_name AND value->'old'<>'null'::jsonb
   UNION SELECT value->'new' FROM jsonb_array_elements(p_domain) WHERE value->>'table'=table_name AND value->'new'<>'null'::jsonb
  LOOP
   work:=work+1;identifier:=row_value->>'id';prior:=result#>ARRAY[map_name,identifier];
   IF coalesce(identifier,'')='' OR (prior IS NOT NULL AND prior IS DISTINCT FROM row_value) THEN
    RAISE EXCEPTION 'CRUD metadata identity has conflicting images' USING ERRCODE='42501';END IF;
   result:=jsonb_set(result,ARRAY[map_name,identifier],row_value);
  END LOOP;
 END LOOP;
 FOR row_value IN
  SELECT value->'row' FROM jsonb_array_elements(coalesce(tables->'access_binding_subjects','[]'::jsonb))
  UNION SELECT value->'new' FROM jsonb_array_elements(p_domain) WHERE value->>'table'='access_binding_subjects' AND value->'new'<>'null'::jsonb
 LOOP
  work:=work+1;identifier:=row_value->>'binding_id';
  IF NOT result->'bindings' ? identifier THEN RAISE EXCEPTION 'CRUD secondary subject owner missing' USING ERRCODE='42501';END IF;
  subjects:=subjects||jsonb_build_object(identifier,coalesce(subjects->identifier,'[]'::jsonb)||jsonb_build_array(row_value));
 END LOOP;
 FOR entry IN SELECT value->'row' FROM jsonb_array_elements(coalesce(tables->'role_rule_selectors','[]'::jsonb)) LOOP
  work:=work+1;
  IF entry->>'arm' IS DISTINCT FROM 'anchor' OR entry->>'container_type' IS NOT NULL THEN
   broad:=broad||jsonb_build_object(entry->>'role_id',true);END IF;
 END LOOP;
 FOREACH table_name IN ARRAY ARRAY['accounts','projects','service_accounts','roles','groups'] LOOP
  FOR entry IN SELECT value FROM jsonb_each(result->table_name) LOOP
   work:=work+1;
   coordinate:=(CASE table_name WHEN 'accounts' THEN 'account' WHEN 'projects' THEN 'project'
    WHEN 'service_accounts' THEN 'iam_service_account' WHEN 'roles' THEN 'iam_role' ELSE 'iam_group' END)||':'||(entry->>'id');
   account_id:=CASE WHEN table_name='accounts' THEN entry->>'id' ELSE entry->>'account_id' END;
   IF coalesce(account_id,'')='' AND coalesce(entry->>'project_id','')<>'' THEN
    account_id:=result#>>ARRAY['projects',entry->>'project_id','account_id'];END IF;
   IF coalesce(account_id,'')<>'' THEN objects:=objects||jsonb_build_object(coordinate,account_id);END IF;
  END LOOP;
 END LOOP;
 IF work>200000 OR octet_length(result::text)+octet_length(subjects::text)>67108864 THEN
  RAISE EXCEPTION 'CRUD metadata index budget exceeded' USING ERRCODE='54000';END IF;
 RETURN result||jsonb_build_object('subjects',subjects,'broad_roles',broad,'object_accounts',objects,'work',work);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Canonical journal metadata имеет собственный bounded read graph:
-- account -> clusters; user -> все memberships, включая чужие accounts.
-- Это metadata уже разрешённого события, не новая область grant authority.
CREATE FUNCTION kaname._authority_crud_journal_capture_v3(p_intent jsonb,p_sources jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE descriptor jsonb;tables jsonb:='{}';rows_value jsonb;user_ids text[];used_rows integer:=0;used_reads integer:=0;
BEGIN
 descriptor:=kaname._authority_crud_intent_v3(p_intent);
 IF p_sources->'descriptor' IS DISTINCT FROM descriptor OR p_rows IS NULL OR p_rows<0 OR p_rows>100000
 OR p_reads IS NULL OR p_reads<0 OR p_reads>4096 THEN
  RAISE EXCEPTION 'invalid CRUD journal capture' USING ERRCODE='42501';END IF;
 IF descriptor->>'command' IN ('account.create','account.delete') THEN
  IF used_reads>=p_reads THEN RAISE EXCEPTION 'CRUD journal cluster read budget exceeded' USING ERRCODE='54000';END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('row',row_value,'xmin',xmin_value,'ctid',ctid_value)
   ORDER BY row_value->>'id'),'[]'::jsonb) INTO rows_value
  FROM (SELECT jsonb_build_object('id',c.id) row_value,c.xmin::text xmin_value,c.ctid::text ctid_value
   FROM ONLY kaname.clusters c ORDER BY c.id LIMIT p_rows-used_rows+1) captured;
  used_reads:=used_reads+1;used_rows:=used_rows+jsonb_array_length(rows_value);
  IF used_rows>p_rows THEN RAISE EXCEPTION 'CRUD journal cluster row budget exceeded' USING ERRCODE='54000';END IF;
  tables:=tables||jsonb_build_object('clusters',rows_value);
 END IF;
 IF descriptor->>'command'='account.delete' THEN
  SELECT coalesce(array_agg(id ORDER BY id COLLATE "C"),ARRAY[]::text[]) INTO user_ids FROM (
   SELECT value->'row'->>'user_id' id FROM jsonb_array_elements(p_sources#>'{tables,memberships}')
   UNION SELECT value->'row'->>'id' FROM jsonb_array_elements(p_sources#>'{tables,users}')
  ) affected;
  IF used_reads>=p_reads THEN RAISE EXCEPTION 'CRUD journal membership read budget exceeded' USING ERRCODE='54000';END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('row',row_value,'xmin',xmin_value,'ctid',ctid_value)
   ORDER BY row_value->>'user_id',row_value->>'account_id'),'[]'::jsonb) INTO rows_value
  FROM (SELECT to_jsonb(m) row_value,m.xmin::text xmin_value,m.ctid::text ctid_value
   FROM ONLY kaname.memberships m WHERE m.user_id=ANY(user_ids)
   ORDER BY m.user_id,m.account_id LIMIT p_rows-used_rows+1) captured;
  used_reads:=used_reads+1;used_rows:=used_rows+jsonb_array_length(rows_value);
  IF used_rows>p_rows THEN RAISE EXCEPTION 'CRUD journal membership row budget exceeded' USING ERRCODE='54000';END IF;
  tables:=tables||jsonb_build_object('memberships',rows_value);
  IF used_reads>=p_reads THEN RAISE EXCEPTION 'CRUD journal owner read budget exceeded' USING ERRCODE='54000';END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('row',row_value,'xmin',xmin_value,'ctid',ctid_value)
   ORDER BY row_value->>'id'),'[]'::jsonb) INTO rows_value
  FROM (SELECT jsonb_build_object('id',u.id) row_value,u.xmin::text xmin_value,u.ctid::text ctid_value
   FROM ONLY kaname.users u WHERE u.id=ANY(user_ids) ORDER BY u.id LIMIT p_rows-used_rows+1) captured;
  used_reads:=used_reads+1;used_rows:=used_rows+jsonb_array_length(rows_value);
  IF used_rows>p_rows THEN RAISE EXCEPTION 'CRUD journal owner row budget exceeded' USING ERRCODE='54000';END IF;
  tables:=tables||jsonb_build_object('users',rows_value);
 END IF;
 RETURN jsonb_build_object('tables',tables,'logical_rows',used_rows,'logical_reads',used_reads);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- SOURCE ONLY: закрытая выдача ID одной команды; не самостоятельная миграция.
-- Наружу выходит только ID проверенного journal effect, никогда nonce/attestation.
-- INSERT остаётся в прежнем INVOKER trigger, поэтому ACL caller не расширяется.
CREATE FUNCTION kaname.authority_resource_crud_journal_value_v3(p_origin jsonb,p_row jsonb) RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;entry jsonb;identifier bigint;claimed jsonb;expected_row jsonb;resolved jsonb;
BEGIN
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NULL OR manifest->'intent'->>'kind' IS DISTINCT FROM 'crud' THEN RETURN NULL;END IF;
 IF manifest->>'registration_program_claimed' IS DISTINCT FROM 'true' OR pg_trigger_depth()<1
 OR jsonb_typeof(p_row) IS DISTINCT FROM 'object' OR jsonb_typeof(p_origin) IS DISTINCT FROM 'object'
 OR jsonb_typeof(manifest#>'{registration_physical,journal}') IS DISTINCT FROM 'array'
 OR jsonb_typeof(manifest#>'{registration_body,claimed_journal_ids}') IS DISTINCT FROM 'array'
 OR jsonb_typeof(manifest#>'{registration_body,resolved_journal}') IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'CRUD journal command missing' USING ERRCODE='42501';END IF;
 claimed:=manifest#>'{registration_body,claimed_journal_ids}';
 resolved:=manifest#>'{registration_body,resolved_journal}';
 -- Origin отличает два user UPDATED одной команды: membership DELETE и
 -- users SET NULL не взаимозаменяемы даже при совпавшем итоговом payload.
 FOR entry IN SELECT value FROM jsonb_array_elements(manifest#>'{registration_physical,journal}') LOOP
  IF entry->'command'=manifest->'object_command' AND entry->'origin'=p_origin
  AND NOT claimed @> jsonb_build_array(entry->'row'->'sequence_no') THEN
   identifier:=(entry->'row'->>'sequence_no')::bigint;expected_row:=entry->'row';EXIT;
  END IF;
 END LOOP;
 IF identifier IS NULL OR identifier<=0 OR NOT resolved ? identifier::text
 OR resolved->identifier::text IS DISTINCT FROM 'null'::jsonb THEN
  RAISE EXCEPTION 'CRUD journal origin outside unconsumed private event' USING ERRCODE='42501';END IF;
 PERFORM kaname._authority_resource_preheld_key_v2(1262569304,identifier::text,true);
 IF entry->>'resolve_user_scope'='true' THEN
  IF manifest->'intent'->>'command' IS DISTINCT FROM 'account.delete'
  OR expected_row->>'resource_kind' IS DISTINCT FROM 'iam_user' OR expected_row->>'event_type' IS DISTINCT FROM 'UPDATED'
  OR NOT ((p_origin->>'table'='memberships' AND p_origin->>'operation'='DELETE')
   OR (p_origin->>'table'='users' AND p_origin->>'operation'='UPDATE')) THEN
   RAISE EXCEPTION 'CRUD journal resolver outside exact account removal callback' USING ERRCODE='42501';END IF;
  -- Только scope уже разрешённого события. Граф memberships защищён до
  -- clock; canonical helper читает собственные предшествующие FK effects.
  -- Новый row/key здесь не заводится: заполняется заранее созданный JSON slot
  -- единственной удержанной private manifest строки.
  expected_row:=jsonb_set(expected_row,'{scope}',kaname.resource_journal_scope('iam_user',
   jsonb_build_object('id',expected_row->>'resource_id')),false);
 END IF;
 IF expected_row-ARRAY['sequence_no','created_at'] IS DISTINCT FROM p_row THEN
  RAISE EXCEPTION 'CRUD journal metadata differs from canonical event' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_authority_resource_manifest
 SET registration_body=jsonb_set(jsonb_set(registration_body,'{claimed_journal_ids}',claimed||jsonb_build_array(identifier)),
  ARRAY['resolved_journal',identifier::text],expected_row,false);
 RETURN identifier;
END $$;

CREATE FUNCTION kaname.authority_crud_journal_applied_v3() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;matches integer;consumed jsonb;
BEGIN
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME<>'resource_journal' OR TG_OP<>'INSERT'
 OR TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' THEN
  RAISE EXCEPTION 'invalid CRUD journal applied context' USING ERRCODE='42501';END IF;
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NULL OR manifest->'intent'->>'kind' IS DISTINCT FROM 'crud' THEN RETURN NULL;END IF;
 consumed:=manifest#>'{registration_body,consumed_journal_ids}';
 SELECT count(*) INTO matches FROM jsonb_array_elements(manifest#>'{registration_physical,journal}') e
 WHERE e->'command'=manifest->'object_command' AND e->'row'->>'sequence_no'=NEW.sequence_no::text
  AND manifest#>ARRAY['registration_body','resolved_journal',NEW.sequence_no::text]=to_jsonb(NEW);
 IF matches<>1 OR jsonb_typeof(consumed) IS DISTINCT FROM 'array'
 OR consumed @> jsonb_build_array(NEW.sequence_no)
 OR NOT (manifest#>'{registration_body,claimed_journal_ids}') @> jsonb_build_array(NEW.sequence_no) THEN
  RAISE EXCEPTION 'CRUD journal insert outside claimed effect' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_authority_resource_manifest
 SET registration_body=jsonb_set(registration_body,'{consumed_journal_ids}',consumed||jsonb_build_array(NEW.sequence_no));
 RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Eventset выводится из фактических table triggers и точных domain images.
-- Каноническая нумерация descriptor не полагается на имена RI callbacks.
CREATE FUNCTION kaname._authority_crud_journal_plan_v3(p_intent jsonb,p_sources jsonb,p_domain jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE descriptor jsonb;image jsonb;row_value jsonb;owner_row jsonb;table_name text;op text;kind text;event text;
 origin jsonb;scope_value jsonb;project_id text;resource_id text;planned jsonb:='[]';entry jsonb;
 bindings jsonb:='{}';deleted_bindings jsonb:='{}';dynamic_scope boolean;trigger_when text;
BEGIN
 descriptor:=kaname._authority_crud_intent_v3(p_intent);
 IF p_sources->'descriptor' IS DISTINCT FROM descriptor OR jsonb_typeof(p_domain) IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'invalid CRUD journal source' USING ERRCODE='42501';END IF;
 FOR entry IN SELECT value FROM jsonb_array_elements(coalesce(p_sources->'scope_bindings','[]'::jsonb)) LOOP
  bindings:=bindings||jsonb_build_object(entry->>'id',entry);
 END LOOP;
 FOR image IN SELECT value FROM jsonb_array_elements(p_domain) LOOP
  table_name:=image->>'table';op:=image->>'operation';dynamic_scope:=false;
  row_value:=CASE WHEN op='DELETE' THEN image->'old' ELSE image->'new' END;
  IF table_name='access_bindings' THEN
   IF op='DELETE' THEN deleted_bindings:=deleted_bindings||jsonb_build_object(row_value->>'id',true);bindings:=bindings-(row_value->>'id');
   ELSE bindings:=bindings||jsonb_build_object(row_value->>'id',row_value);END IF;
  END IF;
  IF table_name IN ('accounts','projects','service_accounts','users','roles','access_bindings') THEN
   IF op='UPDATE' AND image->'old'=image->'new' THEN CONTINUE;END IF;
   kind:=CASE table_name WHEN 'accounts' THEN 'account' WHEN 'projects' THEN 'project' WHEN 'service_accounts' THEN 'iam_service_account'
    WHEN 'users' THEN 'iam_user' WHEN 'roles' THEN 'iam_role' ELSE 'iam_access_binding' END;
   event:=CASE op WHEN 'INSERT' THEN 'CREATED' WHEN 'UPDATE' THEN 'UPDATED' ELSE 'DELETED' END;
   trigger_when:=CASE WHEN op='DELETE' THEN 'BEFORE' ELSE 'AFTER' END;owner_row:=row_value;resource_id:=row_value->>'id';
  ELSIF table_name='access_binding_subjects' THEN
   IF deleted_bindings ? (row_value->>'binding_id') THEN CONTINUE;END IF;
   owner_row:=bindings->(row_value->>'binding_id');
   IF owner_row IS NULL THEN RAISE EXCEPTION 'CRUD journal binding owner omitted' USING ERRCODE='42501';END IF;
   kind:='iam_access_binding';event:='UPDATED';trigger_when:='AFTER';resource_id:=owner_row->>'id';
  ELSIF table_name='memberships' THEN
   SELECT value->'row' INTO owner_row FROM jsonb_array_elements(p_sources#>'{journal_sources,users}')
    WHERE value->'row'->>'id'=row_value->>'user_id';
   IF owner_row IS NULL THEN RAISE EXCEPTION 'CRUD journal user owner omitted' USING ERRCODE='42501';END IF;
   kind:='iam_user';event:='UPDATED';trigger_when:='AFTER';resource_id:=owner_row->>'id';
  ELSE CONTINUE;END IF;
  origin:=jsonb_build_object('table',table_name,'operation',op,'when',trigger_when,'old',image->'old','new',image->'new');
  scope_value:='[]'::jsonb;
  IF kind='account' THEN
   IF jsonb_typeof(p_sources#>'{journal_sources,clusters}') IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'CRUD account journal cluster metadata omitted' USING ERRCODE='42501';END IF;
   SELECT coalesce(jsonb_agg(jsonb_build_object('type','cluster','id',value->'row'->>'id') ORDER BY position),'[]'::jsonb)
    INTO scope_value FROM jsonb_array_elements(p_sources#>'{journal_sources,clusters}') WITH ORDINALITY e(value,position);
  ELSIF kind IN ('project','iam_service_account') AND coalesce(owner_row->>'account_id','')<>'' THEN
   scope_value:=jsonb_build_array(jsonb_build_object('type','account','id',owner_row->>'account_id'));
  ELSIF kind='iam_role' THEN
   IF coalesce(owner_row->>'cluster_id','')<>'' THEN scope_value:=jsonb_build_array(jsonb_build_object('type','cluster','id',owner_row->>'cluster_id'));
   ELSIF coalesce(owner_row->>'account_id','')<>'' THEN scope_value:=jsonb_build_array(jsonb_build_object('type','account','id',owner_row->>'account_id'));
   ELSIF coalesce(owner_row->>'project_id','')<>'' THEN scope_value:=jsonb_build_array(jsonb_build_object('type','project','id',owner_row->>'project_id'));END IF;
  ELSIF kind='iam_access_binding' AND lower(coalesce(owner_row->>'resource_type','')) IN ('project','account','cluster')
   AND coalesce(owner_row->>'resource_id','')<>'' THEN
   scope_value:=jsonb_build_array(jsonb_build_object('type',lower(owner_row->>'resource_type'),'id',owner_row->>'resource_id'));
  ELSIF kind='iam_user' THEN
   IF descriptor->>'command'<>'account.delete' OR event<>'UPDATED'
   OR NOT ((table_name='users' AND op='UPDATE') OR (table_name='memberships' AND op='DELETE')) THEN
    RAISE EXCEPTION 'CRUD dynamic journal event outside closed removal family' USING ERRCODE='42501';END IF;
   dynamic_scope:=true;scope_value:='null'::jsonb;
  END IF;
  project_id:=kaname.resource_journal_project(kind,owner_row);
  planned:=planned||jsonb_build_array(jsonb_build_object('command',image->'command','origin',origin,'resolve_user_scope',dynamic_scope,
   'row',jsonb_build_object('resource_kind',kind,'resource_id',resource_id,'project_id',project_id,'scope',scope_value,
    'event_type',event,'payload',jsonb_build_object('id',resource_id))));
  IF jsonb_array_length(planned)>100000 THEN RAISE EXCEPTION 'CRUD journal event budget exceeded' USING ERRCODE='54000';END IF;
 END LOOP;
 RETURN planned;
END $$;

CREATE FUNCTION kaname._authority_crud_journal_rows_v3(p_plan jsonb,p_ids jsonb,p_tx_at timestamptz) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE result jsonb:='[]';entry jsonb;identifier bigint;previous_id bigint:=0;ordinal integer:=0;
BEGIN
 IF jsonb_typeof(p_plan) IS DISTINCT FROM 'array' OR jsonb_typeof(p_ids) IS DISTINCT FROM 'array'
 OR jsonb_array_length(p_plan)<>jsonb_array_length(p_ids) OR p_tx_at IS NULL THEN
  RAISE EXCEPTION 'CRUD journal reservation count mismatch' USING ERRCODE='42501';END IF;
 FOR entry IN SELECT value FROM jsonb_array_elements(p_plan) LOOP
  identifier:=(p_ids->>ordinal)::bigint;ordinal:=ordinal+1;
  IF identifier IS NULL OR identifier<=previous_id THEN RAISE EXCEPTION 'CRUD journal reserved ID invalid' USING ERRCODE='42501';END IF;
  previous_id:=identifier;
  result:=result||jsonb_build_array(jsonb_set(entry,'{row}',entry->'row'||jsonb_build_object('sequence_no',identifier,'created_at',p_tx_at)));
 END LOOP;
 RETURN result;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- SOURCE ONLY: внутренний фрагмент будущей append migration, не самостоятельная миграция.
-- Один namespace для новых идентичностей; таблица входит в ключ до хеширования.
-- Коллизия hashtext лишь сериализует разные ключи, а равенство строк проверяет PK.
CREATE FUNCTION kaname._authority_crud_unique_key_v3(p_table text,p_row jsonb) RETURNS text
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE key_value jsonb;
BEGIN
 IF jsonb_typeof(p_row) IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'CRUD key row missing' USING ERRCODE='42501';END IF;
 CASE p_table
 WHEN 'accounts','projects','service_accounts','issued_account_ids' THEN
  key_value:=jsonb_build_array(p_table,p_row->>'id');
 WHEN 'project_resource_quotas' THEN
  key_value:=jsonb_build_array(p_table,p_row->>'carrier_type',p_row->>'carrier_id',p_row->>'kind');
 WHEN 'identity_admission_windows' THEN
  key_value:=jsonb_build_array(p_table,p_row->>'carrier_id',p_row->>'kind');
 ELSE RAISE EXCEPTION 'unsupported CRUD key relation' USING ERRCODE='42501';
 END CASE;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(key_value) x WHERE x='null'::jsonb OR x='""'::jsonb) THEN
  RAISE EXCEPTION 'CRUD key incomplete' USING ERRCODE='42501';END IF;
 RETURN key_value::text;
END $$;

CREATE FUNCTION kaname.authority_crud_unique_guard_v3() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE new_key text;old_key text;manifest jsonb;
BEGIN
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW'
 OR TG_OP NOT IN ('INSERT','UPDATE') THEN
  RAISE EXCEPTION 'invalid CRUD unique guard context' USING ERRCODE='42501';END IF;
 new_key:=kaname._authority_crud_unique_key_v3(TG_TABLE_NAME,to_jsonb(NEW));
 IF TG_OP='INSERT' THEN
  -- INSERT уже удерживает RX таблицы; очередь TRUNCATE не оказывается после key.
  manifest:=kaname._authority_producer_resource_v2();
  IF manifest IS NOT NULL AND manifest->'intent'->>'kind'='crud' THEN
   -- Exact prepared body не приобретает незапланированный ключ до row guard.
   PERFORM kaname._authority_resource_preheld_key_v2(1262569303,new_key,true);
  ELSE PERFORM pg_advisory_xact_lock(1262569303,hashtext(new_key));END IF;
 ELSE
  old_key:=kaname._authority_crud_unique_key_v3(TG_TABLE_NAME,to_jsonb(OLD));
  IF old_key=new_key THEN RETURN NEW;END IF;
  -- UPDATE уже взял tuple lock. Здесь запрещено ждать ключ после строки.
  -- Неизменный ключ UPSERT/обычных UPDATE не требует нового ожидания.
  PERFORM kaname._authority_resource_preheld_key_v2(1262569303,old_key,true);
  PERFORM kaname._authority_resource_preheld_key_v2(1262569303,new_key,true);
 END IF;
 RETURN NEW;
END $$;

CREATE FUNCTION kaname._authority_crud_sequence_wait_v3(p_table text,p_count integer,p_reads integer)
RETURNS TABLE(reserved_ids jsonb,held_relations jsonb,held_advisory jsonb,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;table_id oid;sequence_id oid;key_namespace integer;column_name text;
 invoker oid;identifier bigint;present boolean;item record;i integer;
 ids jsonb:='[]'::jsonb;locks jsonb:='[]'::jsonb;used integer:=5;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
 OR proof->>'purpose' IS DISTINCT FROM 'participant' OR proof->>'consumer_abi' IS DISTINCT FROM '2'
 OR proof->>'consumer_finalized' IS DISTINCT FROM 'false'
 OR coalesce(proof->>'consumer_profile','') NOT IN ('resource_pending','resource_source_pending')
 OR current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'CRUD reservation requires pending Resource RC' USING ERRCODE='42501';END IF;
 IF p_count IS NULL OR p_count<1 OR p_count>100000 OR p_reads IS NULL
 OR p_reads<5+2*p_count OR p_reads>4096 THEN
  RAISE EXCEPTION 'CRUD reservation budget exceeded' USING ERRCODE='54000';END IF;
 CASE p_table
 WHEN 'resource_journal' THEN
  table_id:='kaname.resource_journal'::regclass;
  sequence_id:='kaname.resource_journal_sequence_no_seq'::regclass;
  column_name:='sequence_no';key_namespace:=1262569304;
 WHEN 'fga_outbox' THEN
  table_id:='kaname.fga_outbox'::regclass;
  sequence_id:='kaname.fga_outbox_id_seq'::regclass;
  column_name:='id';key_namespace:=1262569305;
 ELSE RAISE EXCEPTION 'unsupported CRUD sequence relation' USING ERRCODE='42501';
 END CASE;
 invoker:=(proof->>'invoker_oid')::oid;
 IF NOT has_table_privilege(invoker,table_id,'INSERT')
 OR NOT has_sequence_privilege(invoker,sequence_id,'USAGE,UPDATE') THEN
  RAISE EXCEPTION 'CRUD reservation requires original INSERT and sequence ACL' USING ERRCODE='42501';END IF;
 EXECUTE format('LOCK TABLE ONLY kaname.%I IN ROW EXCLUSIVE MODE',p_table);
 IF pg_get_serial_sequence(format('kaname.%I',p_table),column_name)::regclass::oid IS DISTINCT FROM sequence_id
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid=table_id OR inhparent=table_id) THEN
  RAISE EXCEPTION 'CRUD sequence schema changed' USING ERRCODE='42501';END IF;
 -- Каждый ID резервируется единожды и передаётся body/trigger для точного INSERT.
 FOR i IN 1..p_count LOOP
  identifier:=nextval(sequence_id);used:=used+1;
  IF identifier<=0 THEN RAISE EXCEPTION 'invalid CRUD sequence ID' USING ERRCODE='P1034';END IF;
  ids:=ids||jsonb_build_array(identifier);
 END LOOP;
 FOR item IN SELECT DISTINCT hashtext(v#>>'{}') h FROM jsonb_array_elements(ids) v ORDER BY h LOOP
  PERFORM pg_advisory_xact_lock(key_namespace,item.h);
  locks:=locks||jsonb_build_array(jsonb_build_object('classid',key_namespace,
   'objid',(item.h::bigint & 4294967295),'objsubid',2,'mode','ExclusiveLock'));
 END LOOP;
 FOR identifier IN SELECT (v#>>'{}')::bigint FROM jsonb_array_elements(ids) v LOOP
  used:=used+1;present:=false;
  EXECUTE format('SELECT true FROM ONLY kaname.%I WHERE %I=$1 FOR UPDATE',p_table,column_name)
   INTO present USING identifier;
  IF coalesce(present,false) THEN RAISE EXCEPTION 'reserved CRUD sequence ID already exists' USING ERRCODE='P1034';END IF;
 END LOOP;
 RETURN QUERY SELECT ids,jsonb_build_array(jsonb_build_object('oid',table_id,'mode','RowExclusiveLock'),
  jsonb_build_object('oid',sequence_id,'mode','RowExclusiveLock')),locks,used;
END $$;

CREATE FUNCTION kaname.authority_crud_sequence_guard_v3() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE key_namespace integer;column_name text;new_key text;old_key text;manifest jsonb;proof jsonb;program jsonb;prepared boolean:=false;
BEGIN
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW'
 OR TG_OP NOT IN ('INSERT','UPDATE') THEN
  RAISE EXCEPTION 'invalid CRUD sequence guard context' USING ERRCODE='42501';END IF;
 CASE TG_TABLE_NAME
 WHEN 'resource_journal' THEN key_namespace:=1262569304;column_name:='sequence_no';
 WHEN 'fga_outbox' THEN key_namespace:=1262569305;column_name:='id';
 ELSE RAISE EXCEPTION 'unsupported CRUD sequence guard relation' USING ERRCODE='42501';
 END CASE;
 new_key:=to_jsonb(NEW)->>column_name;
 IF new_key IS NULL THEN RAISE EXCEPTION 'missing CRUD sequence identity' USING ERRCODE='42501';END IF;
 IF TG_OP='INSERT' THEN
  SELECT q.proof,q.header INTO STRICT proof,program FROM kaname._authority_sequence_probe_v3() q;
  IF proof IS NOT NULL THEN
   prepared:=program IS NOT NULL OR (proof->>'consumer_finalized'='true' AND proof->>'writer_contract'='2') OR kaname._authority_sequence_expected_v3();
  END IF;
  -- Реальный granted RX-conflicting lock исключает обычных producers.
  -- Это физический fastpath Invite, не исключение по kind/profile/token.
  IF kaname._authority_sequence_excluded_v3(TG_RELID) THEN RETURN NEW;END IF;
  IF prepared THEN
   PERFORM kaname._authority_resource_preheld_key_v2(key_namespace,new_key,true);
  ELSE PERFORM pg_advisory_xact_lock(key_namespace,hashtext(new_key));END IF;
 ELSE
  old_key:=to_jsonb(OLD)->>column_name;
  IF old_key=new_key THEN RETURN NEW;END IF;
  PERFORM kaname._authority_resource_preheld_key_v2(key_namespace,old_key,true);
  PERFORM kaname._authority_resource_preheld_key_v2(key_namespace,new_key,true);
 END IF;
 RETURN NEW;
END $$;

-- Все четыре функции private: только owner compiler/actual trigger graph.
DO $$ DECLARE f record;r record;BEGIN
 FOR f IN SELECT p.oid,p.oid::regprocedure signature,p.proowner FROM pg_catalog.pg_proc p
 JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='kaname'
 AND p.proname IN ('_authority_crud_unique_key_v3','authority_crud_unique_guard_v3',
 '_authority_crud_sequence_wait_v3','authority_crud_sequence_guard_v3') LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f.signature);
  FOR r IN SELECT DISTINCT u.rolname FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
   JOIN pg_catalog.pg_roles u ON u.oid=a.grantee WHERE p.oid=f.oid AND a.grantee<>f.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',f.signature,r.rolname);
  END LOOP;
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Верхняя граница metadata выводится без surrogate IDs и без fake rows.
-- Tuple descriptors нужны только для замков; actual write images строятся
-- отдельно из зарезервированных значений и никогда не берутся отсюда.
CREATE FUNCTION kaname._authority_crud_key_maximum_v3(p_intent jsonb,p_sources jsonb,p_program jsonb,p_native_epochs jsonb,p_tx_at timestamptz)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE domain_images jsonb;index_value jsonb;metadata jsonb:='[]';image jsonb;step jsonb;tuple_value jsonb;entry record;
 synthetic jsonb;maximum jsonb;guards jsonb;policy jsonb;identifier text;work integer:=0;
BEGIN
 domain_images:=kaname._authority_crud_domain_images_v3(p_intent,p_sources,p_program,p_tx_at);
 index_value:=kaname._authority_crud_graph_index_v3(p_intent,p_sources,domain_images);
 FOR image IN SELECT value FROM jsonb_array_elements(domain_images)
  WHERE value->>'table' NOT IN ('role_grant_orphan','role_selector_prune') LOOP
  metadata:=metadata||jsonb_build_array(kaname._authority_crud_write_metadata_v3(p_intent,index_value,image));
 END LOOP;
 -- Оба исхода holder/TTL fold охвачены OLD fact и каждой возможной NEW
 -- structural tuple. Это не требует создавать фиктивный FGA outbox ID.
 FOR image IN SELECT value->'row' FROM jsonb_array_elements(p_sources#>'{fold,tables,relation_fact}') LOOP
  synthetic:=jsonb_build_object('table','relation_fact','operation','DELETE','old',image,'new',NULL,'required',true);
  metadata:=metadata||jsonb_build_array(kaname._authority_crud_write_metadata_v3(p_intent,index_value,synthetic));
 END LOOP;
 FOR step IN SELECT value FROM jsonb_array_elements(p_program->'commands')
  WHERE value->>'kind' IN ('fga.tuple.write','fga.tuple.delete') LOOP
  FOR tuple_value IN SELECT value FROM jsonb_array_elements(step->'request') LOOP
   work:=work+1;
   synthetic:=jsonb_build_object('table','fga_outbox','operation','INSERT','old',NULL,'required',true,
    'new',jsonb_build_object('payload',jsonb_build_object('object',tuple_value->>'Object')));
   metadata:=metadata||jsonb_build_array(kaname._authority_crud_write_metadata_v3(p_intent,index_value,synthetic));
   IF tuple_value->>'Relation' NOT LIKE 'v\_%' THEN
    synthetic:=jsonb_build_object('table','relation_fact','operation','INSERT','old',NULL,'required',true,
     'new',jsonb_build_object('object_type',split_part(tuple_value->>'Object',':',1),
      'object_id',substr(tuple_value->>'Object',position(':' IN tuple_value->>'Object')+1),'subject',tuple_value->>'User'));
    metadata:=metadata||jsonb_build_array(kaname._authority_crud_write_metadata_v3(p_intent,index_value,synthetic));
   END IF;
   IF work>100000 OR jsonb_array_length(metadata)>200000 THEN RAISE EXCEPTION 'CRUD metadata work exceeded' USING ERRCODE='54000';END IF;
  END LOOP;
 END LOOP;
 -- Этот maximum принимает две ветви, здесь они уже объединены по tuple
 -- descriptors. Пустая вторая ветвь не добавляет ни эффекта, ни разрешения.
 maximum:=kaname._authority_crud_maximum_v3(jsonb_build_array(jsonb_build_object('writes',metadata),
  jsonb_build_object('writes','[]'::jsonb)),p_native_epochs);
 guards:=maximum->'source_guards';policy:=maximum->'policy_epochs';
 FOR identifier IN SELECT key FROM jsonb_each(index_value->'roles') LOOP
  IF NOT guards ? ('role:'||identifier) THEN guards:=guards||jsonb_build_object('role:'||identifier,'share');END IF;
  IF NOT policy ? ('role:'||identifier) THEN policy:=policy||jsonb_build_object('role:'||identifier,'share');END IF;
 END LOOP;
 FOR identifier IN SELECT key FROM jsonb_each(index_value->'bindings') LOOP
  IF NOT guards ? ('binding:'||identifier) THEN guards:=guards||jsonb_build_object('binding:'||identifier,'share');END IF;
 END LOOP;
 IF (SELECT count(*) FROM jsonb_object_keys(guards))+(SELECT count(*) FROM jsonb_object_keys(policy))
  +(SELECT count(*) FROM jsonb_object_keys(maximum->'binding_epochs'))>4096 THEN
  RAISE EXCEPTION 'CRUD complete metadata key budget exceeded' USING ERRCODE='54000';END IF;
 RETURN maximum||jsonb_build_object('source_guards',guards,'policy_epochs',policy,'graph_index',index_value);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Несколько capture слоёв могут читать проекции одной OLD строки. Для
-- physical prelock они объединяются только при exact xmin/ctid и совместимых
-- значениях полей; полная повторная выборка predicate остаётся обязательной.
CREATE FUNCTION kaname._authority_crud_lock_rows_v3(p_rows jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE result jsonb:='{}';entry jsonb;prior jsonb;field record;key_value text;
BEGIN
 IF jsonb_typeof(p_rows) IS DISTINCT FROM 'array' OR jsonb_array_length(p_rows)>100000 THEN
  RAISE EXCEPTION 'CRUD physical lock source invalid' USING ERRCODE='54000';END IF;
 FOR entry IN SELECT value FROM jsonb_array_elements(p_rows) LOOP
  key_value:=entry->>'ctid';prior:=result->key_value;
  IF coalesce(key_value,'')='' OR entry->>'xmin' IS NULL OR jsonb_typeof(entry->'row') IS DISTINCT FROM 'object' THEN
   RAISE EXCEPTION 'CRUD physical lock source lacks address' USING ERRCODE='42501';END IF;
  IF prior IS NOT NULL THEN
   IF prior->'xmin' IS DISTINCT FROM entry->'xmin' THEN RAISE EXCEPTION 'CRUD physical source generation disagrees' USING ERRCODE='P1034';END IF;
   FOR field IN SELECT * FROM jsonb_each(entry->'row') LOOP
    IF (prior->'row') ? field.key AND prior->'row'->field.key IS DISTINCT FROM field.value THEN
     RAISE EXCEPTION 'CRUD physical source projections disagree' USING ERRCODE='P1034';END IF;
   END LOOP;
   entry:=entry||jsonb_build_object('row',(prior->'row')||(entry->'row'));
  END IF;
  result:=result||jsonb_build_object(key_value,entry);
 END LOOP;
 RETURN (SELECT coalesce(jsonb_agg(value ORDER BY key COLLATE "C"),'[]'::jsonb) FROM jsonb_each(result));
END $$;

CREATE FUNCTION kaname._authority_crud_lock_plan_v3(p_intent jsonb,p_sources jsonb,p_program jsonb,p_tx_at timestamptz)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE descriptor jsonb;tables jsonb;domain_images jsonb;aux jsonb;entry record;image jsonb;row_value jsonb;
 writes jsonb:='{}';keys jsonb:='{}';result jsonb:='{}';table_name text;primary_key jsonb;
BEGIN
 descriptor:=kaname._authority_crud_intent_v3(p_intent);
 tables:=kaname._authority_crud_merge_tables_v3(p_sources->'tables',p_sources->'authority_graph');
 tables:=kaname._authority_crud_merge_tables_v3(tables,p_sources->'journal_sources');
 IF p_sources#>'{primary,row}'<>'null'::jsonb THEN
  tables:=kaname._authority_crud_merge_tables_v3(tables,jsonb_build_object(descriptor->>'table',jsonb_build_array(p_sources->'primary')));END IF;
 IF p_sources#>'{parent,row}'<>'null'::jsonb THEN
  tables:=kaname._authority_crud_merge_tables_v3(tables,jsonb_build_object('accounts',jsonb_build_array(p_sources->'parent')));END IF;
 IF p_sources#>'{owner,row}'<>'null'::jsonb THEN
  tables:=kaname._authority_crud_merge_tables_v3(tables,jsonb_build_object('users',jsonb_build_array(p_sources->'owner')));END IF;
 domain_images:=kaname._authority_crud_domain_images_v3(p_intent,p_sources,p_program,p_tx_at);
 aux:=kaname._authority_crud_aux_images_v3(p_intent,p_sources,p_program,p_tx_at);
 FOR image IN SELECT value FROM jsonb_array_elements(domain_images||aux) LOOP
  table_name:=image->>'table';writes:=writes||jsonb_build_object(table_name,true);
  IF table_name IN ('accounts','projects','service_accounts','issued_account_ids','project_resource_quotas','identity_admission_windows') THEN
   FOR row_value IN SELECT value FROM jsonb_array_elements(jsonb_build_array(image->'old',image->'new')) WHERE value<>'null'::jsonb LOOP
    primary_key:=CASE WHEN table_name IN ('accounts','projects','service_accounts','issued_account_ids') THEN jsonb_build_object('id',row_value->'id')
     WHEN table_name='project_resource_quotas' THEN jsonb_build_object('carrier_type',row_value->'carrier_type','carrier_id',row_value->'carrier_id','kind',row_value->'kind')
     ELSE jsonb_build_object('carrier_id',row_value->'carrier_id','kind',row_value->'kind') END;
    keys:=keys||jsonb_build_object(table_name,coalesce(keys->table_name,'[]'::jsonb)||jsonb_build_array(primary_key));
   END LOOP;
  END IF;
 END LOOP;
 -- DELETE fold может обновить/удалить любой exact captured tuple.
 -- INSERT новых fact gaps защищён полным source/output epoch maximum.
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(p_program->'commands') WHERE value->>'kind' IN ('fga.tuple.write','fga.tuple.delete')) THEN
  writes:=writes||jsonb_build_object('relation_fact',true);END IF;
 FOR entry IN SELECT * FROM jsonb_each(tables) LOOP
  IF entry.key IN ('issued_account_ids','project_resource_quotas','identity_admission_windows') THEN CONTINUE;END IF;
  result:=result||jsonb_build_object(entry.key,kaname._authority_crud_lock_rows_v3(entry.value));
 END LOOP;
 RETURN jsonb_build_object('tables',result,'write_tables',writes,'unique_keys',keys);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Exact normalization повторяет Resource multiplicity; metadata берётся
-- из закрытого CRUD graph, без изменения прежних object/registration ветвей.
CREATE FUNCTION kaname._authority_crud_manifest_images_v3(p_intent jsonb,p_index jsonb,p_direct jsonb,p_fold jsonb)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE images jsonb;prepared jsonb:='[]'::jsonb;writes jsonb:='[]'::jsonb;
 mandatory jsonb:='{}'::jsonb;optional_seen jsonb:='{}'::jsonb;outbox_ordinals jsonb:='[]'::jsonb;
 policy jsonb:='{}'::jsonb;binding_scopes jsonb:='{}'::jsonb;image jsonb;entry jsonb;metadata jsonb;
 canonical_key text;key_value text;table_name text;operation text;work integer:=0;
BEGIN
 IF jsonb_typeof(p_direct) IS DISTINCT FROM 'array' OR jsonb_typeof(p_fold) IS DISTINCT FROM 'array'
 OR jsonb_array_length(p_direct)+jsonb_array_length(p_fold)>100000
 OR octet_length(p_direct::text)+octet_length(p_fold::text)>67108864 THEN
  RAISE EXCEPTION 'CRUD private image budget exceeded' USING ERRCODE='54000';END IF;
 images:=p_direct||p_fold;
 FOR image IN SELECT value FROM jsonb_array_elements(images) LOOP
  table_name:=image->>'table';operation:=image->>'operation';
  IF operation IS NULL OR operation NOT IN ('INSERT','UPDATE','DELETE')
  OR jsonb_typeof(image->'required') IS DISTINCT FROM 'boolean'
  OR coalesce(image->>'command','') !~ '^[1-9][0-9]{0,5}$' OR (image->>'command')::integer>100000
  OR NOT image ?& ARRAY['old','new'] THEN
   RAISE EXCEPTION 'invalid private CRUD effect' USING ERRCODE='42501';END IF;
  IF (operation='INSERT' AND (image->'old'<>'null'::jsonb OR image->'new'='null'::jsonb))
  OR (operation='UPDATE' AND (image->'old'='null'::jsonb OR image->'new'='null'::jsonb))
  OR (operation='DELETE' AND (image->'old'='null'::jsonb OR image->'new'<>'null'::jsonb)) THEN
   RAISE EXCEPTION 'private CRUD operation shape invalid' USING ERRCODE='42501';END IF;
  metadata:=kaname._authority_crud_write_metadata_v3(p_intent,p_index,image);
  entry:=jsonb_build_object('command',image->'command','table',table_name,'operation',operation,
   'old',kaname._authority_resource_row_image_v2(table_name,image->'old'),
   'new',kaname._authority_resource_row_image_v2(table_name,image->'new'),'required',image->'required')||metadata;
  -- Command принадлежит закрытому последовательному шагу. Outbox/clock
  -- слоты остаются физической адресацией, но не дополнительным allow.
  prepared:=prepared||jsonb_build_array(entry);
  canonical_key:=(entry-'required')::text;
  IF entry->>'required'='true' THEN mandatory:=mandatory||jsonb_build_object(canonical_key,true);END IF;
  FOR key_value IN SELECT jsonb_array_elements_text(metadata->'epoch_write_keys') LOOP
   policy:=policy||jsonb_build_object(key_value,'write');
  END LOOP;
  FOR key_value IN SELECT jsonb_array_elements_text(metadata->'binding_epoch_write_scopes') LOOP
   binding_scopes:=binding_scopes||jsonb_build_object(key_value,'write');
  END LOOP;
  work:=work+1+jsonb_array_length(metadata->'epoch_write_keys')+jsonb_array_length(metadata->'binding_epoch_write_scopes');
  IF work>200000 OR (SELECT count(*) FROM jsonb_object_keys(policy))>4096
  OR (SELECT count(*) FROM jsonb_object_keys(binding_scopes))>4096 THEN
   RAISE EXCEPTION 'CRUD private metadata work exceeded' USING ERRCODE='54000';END IF;
 END LOOP;
 FOR entry IN SELECT value FROM jsonb_array_elements(prepared) LOOP
  canonical_key:=(entry-'required')::text;
  IF entry->>'required'='false' THEN
   IF mandatory ? canonical_key THEN
    RAISE EXCEPTION 'same-step attempted and persisted image ambiguity' USING ERRCODE='42501';END IF;
   IF optional_seen ? canonical_key THEN CONTINUE;END IF;
   optional_seen:=optional_seen||jsonb_build_object(canonical_key,true);
  END IF;
  writes:=writes||jsonb_build_array(entry);
  IF entry->>'table'='fga_outbox' THEN
   IF entry->>'operation' IS DISTINCT FROM 'INSERT' OR entry->>'required' IS DISTINCT FROM 'true' THEN
    RAISE EXCEPTION 'CRUD journal must be mandatory insert' USING ERRCODE='42501';END IF;
   outbox_ordinals:=outbox_ordinals||jsonb_build_array(jsonb_array_length(writes));
  END IF;
 END LOOP;
 -- Исторические metadata читатели исключены latch; root строки остаются
 -- shared совместимостью. У OUTPUT нет root UPDATE и нет recipient UPDATE.
 policy:=jsonb_build_object('*','share')||policy;
 binding_scopes:=jsonb_build_object('','share')||binding_scopes;
 RETURN jsonb_build_object('writes',writes,'registration_outbox_write_ordinals',outbox_ordinals,
  'policy_epochs',policy,'binding_epochs',binding_scopes,'work',work);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- После final clock только чистые функции: точные body values, TTL fold,
-- journal resolver slots. Ни строка, ни sequence, ни lock здесь не читаются.
CREATE FUNCTION kaname._authority_resource_crud_materialize_v3(p_intent jsonb,p_certificate jsonb,p_sources jsonb,
 p_prepared jsonb,p_tx_at timestamptz,p_at timestamptz) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE descriptor jsonb;program jsonb;domain_images jsonb;graph_index jsonb;physical jsonb;packed jsonb;
BEGIN
 descriptor:=kaname._authority_crud_intent_v3(p_intent);
 IF p_certificate->'intent' IS DISTINCT FROM p_intent OR p_certificate->>'command' IS DISTINCT FROM descriptor->>'command'
 OR p_sources->'descriptor' IS DISTINCT FROM descriptor OR jsonb_typeof(p_prepared->'reserved') IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_prepared->'held_legacy_keys') IS DISTINCT FROM 'array' OR p_tx_at IS NULL OR p_at IS NULL THEN
  RAISE EXCEPTION 'CRUD final private certificate invalid' USING ERRCODE='42501';END IF;
 program:=kaname._authority_crud_command_plan_v3(p_intent,p_sources);
 domain_images:=kaname._authority_crud_domain_images_v3(p_intent,p_sources,program,p_tx_at);
 graph_index:=kaname._authority_crud_graph_index_v3(p_intent,p_sources,domain_images);
 IF graph_index IS DISTINCT FROM p_certificate->'graph_index' OR program IS DISTINCT FROM p_certificate->'program' THEN
  RAISE EXCEPTION 'CRUD pure graph differs from prepared certificate' USING ERRCODE='42501';END IF;
 physical:=kaname._authority_crud_physical_v3(p_intent,p_sources,program,p_prepared->'reserved',p_tx_at,p_at);
 packed:=kaname._authority_crud_pack_v3(p_intent,graph_index,physical);
 RETURN (packed-'body')||(packed->'body')||jsonb_build_object('held_legacy_keys',p_prepared->'held_legacy_keys');
END $$;

-- Максимум объединяет реальные metadata всех допустимых физических ветвей.
-- Exclusive доминирует shared, но никакой ключ не заменяется wildcard.
CREATE FUNCTION kaname._authority_crud_maximum_v3(p_variants jsonb,p_native_epochs jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE variant jsonb;image jsonb;key_value text;field text;policy jsonb:='{}';guards jsonb:='{}';scopes jsonb:='{}';deferred jsonb:='{}';
 mode_value text;work integer:=0;result jsonb:='{}';keys jsonb;
BEGIN
 IF jsonb_typeof(p_variants) IS DISTINCT FROM 'array' OR jsonb_array_length(p_variants)<>2
 OR jsonb_typeof(p_native_epochs) IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'CRUD maximum branch source missing' USING ERRCODE='42501';END IF;
 FOR variant IN SELECT value FROM jsonb_array_elements(p_variants) LOOP
  IF jsonb_typeof(variant->'writes') IS DISTINCT FROM 'array' THEN
   RAISE EXCEPTION 'CRUD maximum branch writes missing' USING ERRCODE='42501';END IF;
  FOR image IN SELECT value FROM jsonb_array_elements(variant->'writes') LOOP
   FOREACH field IN ARRAY ARRAY['epoch_write_keys','epoch_share_keys','source_guard_write_keys','source_guard_read_keys',
    'binding_epoch_write_scopes','binding_epoch_share_scopes','deferred_carrier_roles'] LOOP
    IF jsonb_typeof(image->field) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'CRUD maximum metadata absent' USING ERRCODE='42501';END IF;
    mode_value:=CASE WHEN field IN ('epoch_write_keys','source_guard_write_keys','binding_epoch_write_scopes','deferred_carrier_roles') THEN 'write' ELSE 'share' END;
    FOR key_value IN SELECT jsonb_array_elements_text(image->field) LOOP
     work:=work+1;
     IF field LIKE 'epoch_%' THEN
      IF mode_value='write' OR NOT policy ? key_value THEN policy:=policy||jsonb_build_object(key_value,mode_value);END IF;
     ELSIF field LIKE 'source_guard_%' THEN
      IF mode_value='write' OR NOT guards ? key_value THEN guards:=guards||jsonb_build_object(key_value,mode_value);END IF;
     ELSIF field LIKE 'binding_epoch_%' THEN
      IF mode_value='write' OR NOT scopes ? key_value THEN scopes:=scopes||jsonb_build_object(key_value,mode_value);END IF;
     ELSE deferred:=deferred||jsonb_build_object(key_value,true);END IF;
    END LOOP;
   END LOOP;
  END LOOP;
 END LOOP;
 FOR key_value IN SELECT jsonb_object_keys(p_native_epochs) LOOP
  work:=work+1;IF NOT policy ? key_value THEN policy:=policy||jsonb_build_object(key_value,'share');END IF;
 END LOOP;
 IF work>400000 OR (SELECT count(*) FROM jsonb_object_keys(policy))>4096
 OR (SELECT count(*) FROM jsonb_object_keys(guards))>4096 OR (SELECT count(*) FROM jsonb_object_keys(scopes))>4096
 OR (SELECT count(*) FROM jsonb_object_keys(deferred))>4096 THEN
  RAISE EXCEPTION 'CRUD maximum key budget exceeded' USING ERRCODE='54000';END IF;
 RETURN jsonb_build_object('policy_epochs',policy,'source_guards',guards,'binding_epochs',scopes,
  'deferred_carrier_roles',kaname._authority_crud_json_keys_v3(deferred),'work',work);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Общая адресация command obligations включает authority rows и отдельные
-- journal/aux slots. Ни attempted-only INSERT, ни частичный шаг не закрывают
-- обязательное сохранённое изменение.
CREATE FUNCTION kaname._authority_crud_pack_v3(p_intent jsonb,p_index jsonb,p_physical jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE compiled jsonb;steps jsonb:='{}';body jsonb;entry record;field text;values_array jsonb;
 command_no integer;ordinal integer;step_count integer;work integer;resolved jsonb:='{}';identifier text;
BEGIN
 IF jsonb_typeof(p_physical) IS DISTINCT FROM 'object' OR jsonb_typeof(p_physical->'commands') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'CRUD physical pack absent' USING ERRCODE='42501';END IF;
 compiled:=kaname._authority_crud_manifest_images_v3(p_intent,p_index,p_physical->'images',p_physical->'fold_images');
 step_count:=jsonb_array_length(p_physical->'commands');
 IF step_count<1 OR step_count>100000
 OR jsonb_array_length(p_physical->'outboxes')<>jsonb_array_length(compiled->'registration_outbox_write_ordinals') THEN
  RAISE EXCEPTION 'CRUD materialization outbox linkage invalid' USING ERRCODE='42501';END IF;
 FOR ordinal IN 1..step_count LOOP
  steps:=steps||jsonb_build_object(ordinal::text,jsonb_build_object('writes','[]'::jsonb,'audits','[]'::jsonb,
   'folds','[]'::jsonb,'bindings','[]'::jsonb,'reconcile','[]'::jsonb,'subject_changes','[]'::jsonb,
   'journal','[]'::jsonb,'fga_ids','[]'::jsonb,'aux','[]'::jsonb));
 END LOOP;
 FOREACH field IN ARRAY ARRAY['writes','audits','folds','bindings','reconcile','subject_changes','journal','fga_ids','aux'] LOOP
  values_array:=CASE field WHEN 'writes' THEN compiled->'writes'
   WHEN 'folds' THEN p_physical->'outboxes' WHEN 'fga_ids' THEN p_physical->'outboxes' ELSE p_physical->field END;
  IF jsonb_typeof(values_array) IS DISTINCT FROM 'array' THEN
   RAISE EXCEPTION 'CRUD effect array missing' USING ERRCODE='42501';END IF;
  FOR entry IN SELECT value,position FROM jsonb_array_elements(values_array) WITH ORDINALITY q(value,position) LOOP
   command_no:=(entry.value->>'command')::integer;
   IF command_no IS NULL OR command_no<1 OR command_no>step_count THEN
    RAISE EXCEPTION 'CRUD effect command outside actual program' USING ERRCODE='42501';END IF;
   IF field IN ('writes','bindings','aux') THEN
    IF jsonb_typeof(entry.value->'required') IS DISTINCT FROM 'boolean' THEN
     RAISE EXCEPTION 'CRUD mandatory effect marker absent' USING ERRCODE='42501';END IF;
    IF entry.value->>'required'='false' THEN CONTINUE;END IF;
   END IF;
   steps:=jsonb_set(steps,ARRAY[command_no::text,field],steps#>ARRAY[command_no::text,field]||
    jsonb_build_array(CASE WHEN field IN ('writes','folds','bindings','aux') THEN to_jsonb(entry.position)
     WHEN field='fga_ids' THEN entry.value->'id' WHEN field='journal' THEN entry.value#>'{row,sequence_no}'
     ELSE entry.value#>'{row,id}' END));
   IF field='journal' THEN
    identifier:=entry.value#>>'{row,sequence_no}';
    IF coalesce(identifier,'')='' OR resolved ? identifier THEN
     RAISE EXCEPTION 'CRUD journal resolver slot duplicated' USING ERRCODE='42501';END IF;
    resolved:=resolved||jsonb_build_object(identifier,NULL);
   END IF;
  END LOOP;
 END LOOP;
 body:=jsonb_build_object('consumed_journal_ids','[]'::jsonb,'claimed_journal_ids','[]'::jsonb,
  'consumed_fga_ids','[]'::jsonb,'consumed_aux','[]'::jsonb,'resolved_journal',resolved);
 work:=(p_physical->>'work')::integer+(compiled->>'work')::integer+step_count;
 IF work>400000 THEN RAISE EXCEPTION 'CRUD packing work exceeded' USING ERRCODE='54000';END IF;
 RETURN compiled||jsonb_build_object('physical',p_physical,'step_obligations',steps,
  'program',jsonb_build_object('commands',p_physical->'commands'),'body',body,'result','{}'::jsonb,'work',work);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Чистая materialization использует только заранее зарезервированные ID.
-- nextval, чтение строк и ожидания после final clock отсутствуют.
CREATE FUNCTION kaname._authority_crud_physical_v3(p_intent jsonb,p_sources jsonb,p_program jsonb,p_reserved jsonb,
 p_tx_at timestamptz,p_at timestamptz) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE descriptor jsonb;domain_images jsonb;domain_only jsonb;aux jsonb;folded jsonb;index_value jsonb;
 commands jsonb:='[]';outboxes jsonb:='[]';audits jsonb:='[]';reconcile jsonb:='[]';journal jsonb;
 step jsonb;request jsonb;reserved jsonb;row_value jsonb;payload jsonb;entry jsonb;ids jsonb;operations jsonb;
 ordinal integer:=0;kind text;table_name text;operation text;work integer:=0;identifier text;
BEGIN
 descriptor:=kaname._authority_crud_intent_v3(p_intent);
 IF p_tx_at IS NULL OR p_at IS NULL OR p_sources->'descriptor' IS DISTINCT FROM descriptor
 OR p_program IS DISTINCT FROM kaname._authority_crud_command_plan_v3(p_intent,p_sources)
 OR jsonb_typeof(p_reserved->'commands') IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_reserved->'journal_ids') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'CRUD physical source not closed' USING ERRCODE='42501';END IF;
 domain_images:=kaname._authority_crud_domain_images_v3(p_intent,p_sources,p_program,p_tx_at);
 aux:=kaname._authority_crud_aux_images_v3(p_intent,p_sources,p_program,p_tx_at);
 -- Эти две FK таблицы не входят в authority row-image codec. Их exact
 -- DELETE охраняется отдельным auxiliary guard, без второго разрешения.
 SELECT coalesce(jsonb_agg(value ORDER BY ord),'[]'::jsonb) INTO domain_only
 FROM jsonb_array_elements(domain_images) WITH ORDINALITY q(value,ord)
 WHERE value->>'table' NOT IN ('role_grant_orphan','role_selector_prune');
 SELECT aux||coalesce(jsonb_agg(value ORDER BY ord),'[]'::jsonb) INTO aux
 FROM jsonb_array_elements(domain_images) WITH ORDINALITY q(value,ord)
 WHERE value->>'table' IN ('role_grant_orphan','role_selector_prune');
 FOR step IN SELECT value FROM jsonb_array_elements(p_program->'commands') LOOP
  ordinal:=ordinal+1;kind:=step->>'kind';request:=step->'request';reserved:=p_reserved->'commands'->ordinal::text;
  IF jsonb_typeof(reserved) IS DISTINCT FROM 'object' THEN
   RAISE EXCEPTION 'CRUD command reservation missing' USING ERRCODE='42501';END IF;
  IF kind IN ('audit','binding.audit') THEN
   identifier:=reserved->>'audit_id';
   IF coalesce(identifier,'') !~ '^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$' OR reserved-'audit_id'<>'{}'::jsonb THEN
    RAISE EXCEPTION 'CRUD audit reservation invalid' USING ERRCODE='42501';END IF;
   IF kind='audit' THEN payload:=request->'Payload';
   ELSE payload:=jsonb_build_object('actor',request->>'Actor','subject_type',request->>'SubjectType',
    'subject_id',request->>'SubjectID','resource_type',request->>'ResourceType','resource_id',request->>'ResourceID',
    'role_id',request->>'RoleID','binding_id',request->>'BindingID')||coalesce(nullif(request->'ExtraPayload','null'::jsonb),'{}'::jsonb);END IF;
   row_value:=jsonb_build_object('id',identifier,'event_type',request->>'EventType',
    'tenant_account_id',nullif(request->>'TenantAccountID',''),'event_payload',payload,
    'status','pending','attempts',0,'created_at',p_tx_at,'next_attempt_at',p_tx_at,'sent_at',NULL,'last_error',NULL);
   audits:=audits||jsonb_build_array(jsonb_build_object('command',ordinal,'row',row_value));
   step:=step||jsonb_build_object('row',row_value);
  ELSIF kind='reconcile' THEN
   IF coalesce(reserved->>'reconcile_id','') !~ '^[1-9][0-9]{0,18}$' OR reserved-'reconcile_id'<>'{}'::jsonb THEN
    RAISE EXCEPTION 'CRUD reconcile reservation invalid' USING ERRCODE='42501';END IF;
   row_value:=jsonb_build_object('id',(reserved->>'reconcile_id')::bigint,'event_type',request->>'EventType',
    'object_type',request->>'ObjectType','object_id',request->>'ObjectID','created_at',p_tx_at,
    'sent_at',NULL,'last_error',NULL,'attempt_count',0);
   reconcile:=reconcile||jsonb_build_array(jsonb_build_object('command',ordinal,'row',row_value));
   step:=step||jsonb_build_object('row',row_value);
  ELSIF kind IN ('fga.tuple.write','fga.tuple.delete') THEN
   ids:=reserved->'fga_ids';
   IF reserved-'fga_ids'<>'{}'::jsonb THEN RAISE EXCEPTION 'CRUD FGA reservation has extra values' USING ERRCODE='42501';END IF;
   outboxes:=outboxes||kaname._authority_crud_fga_rows_v3(request,kind,ids,ordinal,
    CASE WHEN kind='fga.tuple.delete' THEN p_at ELSE p_tx_at END);
   step:=step||jsonb_build_object('ids',ids);
  ELSIF reserved<>'{}'::jsonb THEN RAISE EXCEPTION 'CRUD command has unused reservation' USING ERRCODE='42501';
  END IF;
  commands:=commands||jsonb_build_array(step);
 END LOOP;
 IF (SELECT count(*) FROM jsonb_object_keys(p_reserved->'commands'))<>ordinal THEN
  RAISE EXCEPTION 'CRUD reservation command multiplicity mismatch' USING ERRCODE='42501';END IF;
 folded:=kaname._authority_crud_fold_images_v3(p_program,domain_images,outboxes,p_sources->'fold',p_tx_at,p_at);
 FOR entry IN SELECT value FROM jsonb_array_elements(outboxes) LOOP
  domain_only:=domain_only||kaname._authority_crud_image_v3((entry->>'command')::integer,'fga_outbox','INSERT',NULL,entry->'row');
 END LOOP;
 journal:=kaname._authority_crud_journal_rows_v3(
  kaname._authority_crud_journal_plan_v3(p_intent,p_sources,domain_images),p_reserved->'journal_ids',p_tx_at);
 -- Statement admission остаётся точной проекцией actual row programs.
 -- Пропущенная команда не получает blanket-разрешение на таблицу.
 FOR ordinal IN 1..jsonb_array_length(commands) LOOP
  operations:='{}';step:=commands->(ordinal-1);kind:=step->>'kind';
  FOR entry IN SELECT value FROM jsonb_array_elements(domain_only||(folded->'images')||aux)
   WHERE (value->>'command')::integer=ordinal LOOP
   table_name:=entry->>'table';operation:=entry->>'operation';
   IF NOT coalesce(operations->table_name,'[]'::jsonb) ? operation THEN
    operations:=operations||jsonb_build_object(table_name,coalesce(operations->table_name,'[]'::jsonb)||jsonb_build_array(operation));END IF;
  END LOOP;
  -- Fold images связаны с командой через exact outbox ordinal, а не поле command.
  -- ON CONFLICT DO UPDATE выполняет UPDATE statement trigger и без UPDATE rows.
  FOR entry IN SELECT value FROM jsonb_array_elements(folded->'images')
   WHERE outboxes->((value->>'outbox')::integer-1)->'command'=to_jsonb(ordinal) LOOP
   table_name:=entry->>'table';operation:=entry->>'operation';
   IF NOT coalesce(operations->table_name,'[]'::jsonb) ? operation THEN
    operations:=operations||jsonb_build_object(table_name,coalesce(operations->table_name,'[]'::jsonb)||jsonb_build_array(operation));END IF;
   IF table_name='relation_fact' AND operation='INSERT' AND NOT operations->table_name ? 'UPDATE' THEN
    operations:=operations||jsonb_build_object(table_name,(operations->table_name)||'["UPDATE"]'::jsonb);END IF;
  END LOOP;
  IF kind='account.insert' AND coalesce(operations->'identity_admission_windows','[]'::jsonb) ? 'INSERT'
   AND NOT operations->'identity_admission_windows' ? 'UPDATE' THEN
   operations:=operations||jsonb_build_object('identity_admission_windows',(operations->'identity_admission_windows')||'["UPDATE"]'::jsonb);
  END IF;
  IF kind IN ('audit','binding.audit') THEN operations:=operations||jsonb_build_object('audit_outbox','["INSERT"]'::jsonb);END IF;
  IF kind='reconcile' THEN operations:=operations||jsonb_build_object('resource_reconcile_outbox','["INSERT"]'::jsonb);END IF;
  -- DELETE/INSERT с нулевым row count всё ещё выполняют statement trigger.
  -- Только реальный вызов конкретного шага добавляет его фиксированную таблицу.
  IF kind IN ('binding.subjects','binding.ledger') THEN
   table_name:=CASE kind WHEN 'binding.subjects' THEN 'access_binding_subjects' ELSE 'access_binding_emitted_tuples' END;
   operations:=operations||jsonb_build_object(table_name,'["INSERT"]'::jsonb);
  END IF;
  IF kind='binding.delete' THEN
   FOREACH table_name IN ARRAY ARRAY['access_bindings','access_binding_subjects','access_binding_target_members','access_binding_emitted_tuples'] LOOP
    operations:=operations||jsonb_build_object(table_name,'["DELETE"]'::jsonb);
   END LOOP;
  ELSIF kind='account.delete' THEN
   operations:=operations||jsonb_build_object('accounts','["DELETE"]'::jsonb,'memberships','["DELETE"]'::jsonb,'users','["UPDATE"]'::jsonb);
   -- FK users.account_id SET NULL запускает membership mirror, включая zero-row UPDATE.
   -- Разрешён только statement текущей compiled users UPDATE; row matcher не меняется.
   IF EXISTS(SELECT 1 FROM jsonb_array_elements(domain_only) w
    WHERE w->'command'=to_jsonb(ordinal) AND w->>'table'='users' AND w->>'operation'='UPDATE') THEN
    operations:=operations||jsonb_build_object('memberships','["DELETE","UPDATE"]'::jsonb);
   END IF;
  ELSIF kind='role.delete' THEN
   FOREACH table_name IN ARRAY ARRAY['roles','access_binding_target_members','role_rule_selectors','role_selector_verbs_pending',
    'role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule','role_grant_orphan','role_selector_prune'] LOOP
    operations:=operations||jsonb_build_object(table_name,'["DELETE"]'::jsonb);
   END LOOP;
  END IF;
  commands:=jsonb_set(commands,ARRAY[(ordinal-1)::text],step||jsonb_build_object('operations',operations));
 END LOOP;
 work:=jsonb_array_length(domain_images)+jsonb_array_length(aux)+jsonb_array_length(commands)+jsonb_array_length(outboxes)
  +jsonb_array_length(audits)+jsonb_array_length(reconcile)+jsonb_array_length(journal)+(folded->>'work')::integer;
 IF work>400000 THEN RAISE EXCEPTION 'CRUD physical work budget exceeded' USING ERRCODE='54000';END IF;
 RETURN jsonb_build_object('commands',commands,'images',domain_only,'fold_images',folded->'images','outboxes',outboxes,
  'audits',audits,'reconcile',reconcile,'journal',journal,'aux',aux,'bindings','[]'::jsonb,'subject_changes','[]'::jsonb,'work',work);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Единственный CRUD compiler entry. Caller RR capture является ожиданием
-- для повторного чтения, а не доверенной программой. Никакой clock здесь нет.
CREATE FUNCTION kaname._authority_resource_crud_prepare_v3(p_envelope jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;intent jsonb;descriptor jsonb;captured jsonb;after_capture jsonb;sources jsonb;program jsonb;maximum jsonb;
 lock_plan jsonb;part jsonb;reserved jsonb;certificate jsonb;native_epochs jsonb:='{}';legacy_keys jsonb:='[]';
 held_relations jsonb:='[]';held_advisory jsonb:='[]';entry record;epoch_result record;bundle_result record;unique_result record;
 key_value text;table_name text;tuple_rows jsonb;used_rows integer:=0;used_reads integer:=0;compiled jsonb;preview jsonb;
BEGIN
 proof:=kaname.authority_protocol_attestation();intent:=p_envelope->'intent';descriptor:=kaname._authority_crud_intent_v3(intent);
 IF proof IS NULL OR proof->>'writer_contract' IS DISTINCT FROM '2' OR proof->>'kind' IS DISTINCT FROM 'resource'
 OR proof->>'purpose' IS DISTINCT FROM 'participant' OR proof->>'consumer_abi' IS DISTINCT FROM '2'
 OR proof->>'consumer_profile' IS DISTINCT FROM 'resource_source_pending' OR proof->>'consumer_finalized' IS DISTINCT FROM 'false'
 OR current_setting('transaction_isolation')<>'read committed' OR to_regclass('pg_temp.kaname_authority_resource_manifest') IS NOT NULL
 OR p_envelope-'abi'-'intent'-'crud_capture'-'native_epochs'<>'{}'::jsonb OR p_envelope->'abi' IS DISTINCT FROM '2'::jsonb
 OR jsonb_typeof(p_envelope->'crud_capture') IS DISTINCT FROM 'object' OR jsonb_typeof(p_envelope->'native_epochs') IS DISTINCT FROM 'object'
 OR NOT coalesce((p_envelope->'native_epochs') ? (intent->>'actor'),false)
 OR p_rows IS NULL OR p_rows<1 OR p_rows>100000 OR p_reads IS NULL OR p_reads<1 OR p_reads>4096
 OR (descriptor->>'global'='true' AND proof->>'mode' IS DISTINCT FROM 'global')
 OR (descriptor->>'global'='false' AND (proof->>'mode' IS DISTINCT FROM 'accounts'
  OR proof->'accounts' IS DISTINCT FROM jsonb_build_array(descriptor->>'account'))) THEN
  RAISE EXCEPTION 'CRUD prewait requires exact pending full source admission' USING ERRCODE='42501';END IF;
 SELECT * INTO STRICT bundle_result FROM kaname._authority_resource_bundle_catalog_v2(p_rows,p_reads);
 used_rows:=used_rows+bundle_result.logical_rows;used_reads:=used_reads+bundle_result.logical_reads;
 captured:=kaname._authority_crud_capture_v3(intent,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+(captured->>'logical_rows')::integer;used_reads:=used_reads+(captured->>'logical_reads')::integer;
 IF captured-ARRAY['logical_rows','logical_reads'] IS DISTINCT FROM
  (p_envelope->'crud_capture')-ARRAY['logical_rows','logical_reads'] THEN
  RAISE EXCEPTION 'CRUD source changed since RR stage' USING ERRCODE='P1034';END IF;
 sources:=captured->'sources';program:=kaname._authority_crud_command_plan_v3(intent,sources);
 maximum:=kaname._authority_crud_key_maximum_v3(intent,sources,program,p_envelope->'native_epochs',transaction_timestamp());
 part:=kaname._authority_crud_relation_wait_v3(intent,sources,program,p_reads-used_reads);
 used_reads:=used_reads+(part->>'logical_reads')::integer;held_relations:=held_relations||(part->'held_relations');
 SELECT * INTO STRICT epoch_result FROM kaname._authority_resource_epoch_wait_v2(maximum->'source_guards',maximum->'policy_epochs',
  maximum->'binding_epochs',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+epoch_result.logical_rows;used_reads:=used_reads+epoch_result.logical_reads;
 FOR entry IN SELECT * FROM jsonb_each(p_envelope->'native_epochs') LOOP
  IF epoch_result.lock_witness->'policy_before'->entry.key IS DISTINCT FROM entry.value THEN
   RAISE EXCEPTION 'CRUD native source changed before protected entry' USING ERRCODE='P1034';END IF;
  -- Только отсутствовавший WRITE epoch мог быть создан этим acquisition.
  -- Старая generation/revision никогда не заменяется новой producer revision.
  native_epochs:=native_epochs||jsonb_build_object(entry.key,epoch_result.lock_witness->'policy_after'->entry.key);
 END LOOP;
 held_advisory:=epoch_result.lock_witness->'held_advisory';
 SELECT coalesce(jsonb_agg(value->'id' ORDER BY value->>'id' COLLATE "C"),'[]'::jsonb) INTO legacy_keys
 FROM jsonb_array_elements(sources->'scope_bindings');
 IF jsonb_array_length(legacy_keys)>p_reads-used_reads THEN RAISE EXCEPTION 'CRUD legacy lock budget exceeded' USING ERRCODE='54000';END IF;
 FOR entry IN SELECT DISTINCT hashtext(value#>>'{}') hashed FROM jsonb_array_elements(legacy_keys) ORDER BY hashed LOOP
  PERFORM pg_advisory_xact_lock(entry.hashed::bigint);used_reads:=used_reads+1;
  held_advisory:=held_advisory||jsonb_build_array(jsonb_build_object('classid',CASE WHEN entry.hashed<0 THEN 4294967295::bigint ELSE 0 END,
   'objid',(entry.hashed::bigint & 4294967295),'objsubid',1,'mode','ExclusiveLock'));
 END LOOP;
 lock_plan:=kaname._authority_crud_lock_plan_v3(intent,sources,program,transaction_timestamp());
 -- Порядок root/child совпадает у всех семи prepared команд. Consumer и
 -- полный authority key набор уже удержаны; raw/default writer не подписан.
 FOREACH table_name IN ARRAY ARRAY['users','accounts','projects','service_accounts','roles','groups','memberships',
  'access_bindings','access_binding_subjects','access_binding_target_members','access_binding_emitted_tuples',
  'role_rule_selectors','role_selector_verbs_pending','role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule',
  'role_grant_orphan','role_selector_prune','service_account_oauth_clients','relation_fact','resource_registration_pointer',
  'resource_registration_retirement','cluster_admin_grants','clusters','own_ceilings','account_admission_rate_limits'] LOOP
  IF NOT lock_plan->'tables' ? table_name THEN CONTINUE;END IF;
  tuple_rows:=lock_plan->'tables'->table_name;
  part:=kaname._authority_crud_tuple_wait_v3(table_name,tuple_rows,lock_plan->'write_tables' ? table_name,p_rows-used_rows,p_reads-used_reads);
  used_rows:=used_rows+(part->>'logical_rows')::integer;used_reads:=used_reads+(part->>'logical_reads')::integer;
  held_relations:=held_relations||(part->'held_relations');
 END LOOP;
 -- Root rows до auxiliary key/row waits: тот же порядок, что у реального
 -- INSERT/DELETE и их quota/issued-ID триггеров. Внутри таблицы RX→key→row.
 FOREACH table_name IN ARRAY ARRAY['accounts','projects','service_accounts','issued_account_ids','project_resource_quotas','identity_admission_windows'] LOOP
  IF NOT lock_plan->'unique_keys' ? table_name THEN CONTINUE;END IF;
  SELECT * INTO STRICT unique_result FROM kaname._authority_crud_unique_wait_v3(table_name,lock_plan->'unique_keys'->table_name,
   p_rows-used_rows,p_reads-used_reads);
  used_rows:=used_rows+unique_result.logical_rows;used_reads:=used_reads+unique_result.logical_reads;
  held_relations:=held_relations||unique_result.held_relations;held_advisory:=held_advisory||unique_result.held_advisory;
 END LOOP;
 reserved:=kaname._authority_crud_reserve_v3(intent,sources,program,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+(reserved->>'logical_rows')::integer;used_reads:=used_reads+(reserved->>'logical_reads')::integer;
 held_relations:=held_relations||(reserved->'held_relations');held_advisory:=held_advisory||(reserved->'held_advisory');
 after_capture:=kaname._authority_crud_capture_v3(intent,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+(after_capture->>'logical_rows')::integer;used_reads:=used_reads+(after_capture->>'logical_reads')::integer;
 IF after_capture-ARRAY['logical_rows','logical_reads'] IS DISTINCT FROM captured-ARRAY['logical_rows','logical_reads'] THEN
  RAISE EXCEPTION 'CRUD protected source graph changed during waits' USING ERRCODE='P1034';END IF;
 certificate:=jsonb_build_object('intent',intent,'command',descriptor->>'command','program',program,'graph_index',maximum->'graph_index');
 compiled:=jsonb_build_object('intent',intent,'certificate',certificate,'sources',sources,
  'prepared',jsonb_build_object('reserved',reserved->'reserved','held_legacy_keys',legacy_keys),
  'maximum',maximum,'native_epochs',native_epochs,'epoch_witness',epoch_result.lock_witness,
  'held_relations',held_relations,'held_advisory',held_advisory,'catalog_rows','[]'::jsonb);
 IF used_rows>p_rows OR used_reads>p_reads OR jsonb_array_length(held_advisory)>4096 OR jsonb_array_length(held_relations)>256 THEN
  RAISE EXCEPTION 'CRUD total physical prewait budget exceeded' USING ERRCODE='54000';END IF;
 PERFORM kaname._authority_resource_crud_store_v3(compiled);
 RETURN QUERY SELECT used_rows,used_reads;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Relation-only preflight закрывает также zero-row FK statements и
-- owner-private epoch/pending tables. ROW EXCLUSIVE не сериализует обычный
-- чужой account DML; arbitrary runtime TRUNCATE остаётся отдельной liveness границей.
CREATE FUNCTION kaname._authority_crud_relation_wait_v3(p_intent jsonb,p_sources jsonb,p_program jsonb,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE descriptor jsonb;tables jsonb:='{}';entry record;image jsonb;table_name text;relation_id oid;proof jsonb;
 held jsonb:='[]';used_reads integer:=0;domain_images jsonb;aux jsonb;command_kind text;read_table text;lock_mode text;
BEGIN
 proof:=kaname.authority_protocol_attestation();descriptor:=kaname._authority_crud_intent_v3(p_intent);
 IF proof IS NULL OR proof->>'writer_contract' IS DISTINCT FROM '2' OR proof->>'consumer_profile' IS DISTINCT FROM 'resource_source_pending'
 OR proof->>'consumer_finalized' IS DISTINCT FROM 'false' OR p_reads IS NULL OR p_reads<1 OR p_reads>4096 THEN
  RAISE EXCEPTION 'CRUD relation preflight admission invalid' USING ERRCODE='42501';END IF;
 domain_images:=kaname._authority_crud_domain_images_v3(p_intent,p_sources,p_program,transaction_timestamp());
 aux:=kaname._authority_crud_aux_images_v3(p_intent,p_sources,p_program,transaction_timestamp());
 FOR image IN SELECT value FROM jsonb_array_elements(domain_images||aux) LOOP
  tables:=tables||jsonb_build_object(image->>'table',true);
 END LOOP;
 FOR command_kind IN SELECT value->>'kind' FROM jsonb_array_elements(p_program->'commands') LOOP
  IF command_kind='binding.delete' THEN
   tables:=tables||'{"access_bindings":true,"access_binding_subjects":true,"access_binding_target_members":true,"access_binding_emitted_tuples":true}'::jsonb;
  ELSIF command_kind='account.delete' THEN tables:=tables||'{"accounts":true,"memberships":true,"users":true}'::jsonb;
  ELSIF command_kind='role.delete' THEN
   tables:=tables||'{"roles":true,"access_binding_target_members":true,"role_rule_selectors":true,"role_selector_verbs_pending":true,"role_verb":true,"role_rule_ref":true,"role_create_binding_rule":true,"role_bind_role_rule":true,"role_grant_orphan":true,"role_selector_prune":true}'::jsonb;
  ELSIF command_kind IN ('fga.tuple.write','fga.tuple.delete') THEN
   tables:=tables||'{"fga_outbox":true,"relation_fact":true}'::jsonb;
  END IF;
 END LOOP;
 -- Ветви отказа при отсутствующей posture также держат relation locks.
 -- Concurrent config INSERT не разрешает новый effect: exact row guard
 -- отвергнет его до unique arbitration, но RX не должен ждать после clock.
 IF descriptor->>'command'='account.create' THEN
  tables:=tables||'{"issued_account_ids":true,"project_resource_quotas":true,"identity_admission_windows":true}'::jsonb;
 ELSIF descriptor->>'command'='service_account.create' THEN
  tables:=tables||'{"project_resource_quotas":true}'::jsonb;
 END IF;
 -- Отказные SELECT исходных Delete выполняются даже при пустом child set.
 -- Их relation locks тоже получены заранее; rows/явные отказы не заменяются.
 IF descriptor->>'command'='project.delete' THEN
  FOREACH read_table IN ARRAY ARRAY['roles','resource_mirror'] LOOP
   IF NOT tables ? read_table THEN tables:=tables||jsonb_build_object(read_table,false);END IF;
  END LOOP;
 ELSIF descriptor->>'command'='account.delete' THEN
  FOREACH read_table IN ARRAY ARRAY['projects','service_accounts','groups','roles'] LOOP
   IF NOT tables ? read_table THEN tables:=tables||jsonb_build_object(read_table,false);END IF;
  END LOOP;
 END IF;
 tables:=tables||'{"authority_policy_epoch":true,"authority_binding_epoch":true,"authority_policy_carrier_pending":true}'::jsonb;
 IF (SELECT count(*) FROM jsonb_object_keys(tables))*2>p_reads THEN
  RAISE EXCEPTION 'CRUD relation preflight budget exceeded' USING ERRCODE='54000';END IF;
 FOR table_name IN SELECT key FROM jsonb_each(tables) ORDER BY to_regclass(format('kaname.%I',key))::oid LOOP
  IF table_name NOT IN ('accounts','projects','service_accounts','groups','users','memberships','roles','access_bindings',
   'access_binding_subjects','access_binding_target_members','access_binding_emitted_tuples','role_rule_selectors',
   'role_selector_verbs_pending','role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule','role_grant_orphan',
   'role_selector_prune','resource_mirror','fga_outbox','relation_fact','issued_account_ids','project_resource_quotas','identity_admission_windows',
   'authority_policy_epoch','authority_binding_epoch','authority_policy_carrier_pending') THEN
   RAISE EXCEPTION 'CRUD relation preflight escaped finite graph' USING ERRCODE='42501';END IF;
  relation_id:=to_regclass(format('kaname.%I',table_name));used_reads:=used_reads+1;
  IF relation_id IS NULL OR EXISTS(SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid=relation_id OR inhparent=relation_id) THEN
   RAISE EXCEPTION 'CRUD relation preflight schema mismatch' USING ERRCODE='42501';END IF;
  lock_mode:=CASE WHEN tables->>table_name='true' THEN 'ROW EXCLUSIVE' ELSE 'ACCESS SHARE' END;
  EXECUTE format('LOCK TABLE ONLY kaname.%I IN %s MODE',table_name,lock_mode);used_reads:=used_reads+1;
  held:=held||jsonb_build_array(jsonb_build_object('oid',relation_id,'mode',CASE WHEN lock_mode='ROW EXCLUSIVE' THEN 'RowExclusiveLock' ELSE 'AccessShareLock' END));
 END LOOP;
 RETURN jsonb_build_object('held_relations',held,'logical_reads',used_reads);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Весь набор surrogate keys выводится из actual command plan до clock.
-- Генерация не вставляет placeholder rows и не подменяет бизнес-эффект.
CREATE FUNCTION kaname._authority_crud_reserve_v3(p_intent jsonb,p_sources jsonb,p_program jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE step jsonb;entry record;command_no integer:=0;audit_ids jsonb:='{}';command_values jsonb:='{}';counts jsonb:='{}';
 domain_images jsonb;journal_plan jsonb;journal_ids jsonb:='[]';fga_ids jsonb:='[]';reconcile_ids jsonb:='[]';
 identifier text;fga_count integer:=0;reconcile_count integer:=0;group_count integer;cursor_fga integer:=0;cursor_reconcile integer:=0;
 used_rows integer:=0;used_reads integer:=0;held_relations jsonb:='[]';held_advisory jsonb:='[]';part record;sliced jsonb;
BEGIN
 IF p_rows IS NULL OR p_rows<0 OR p_rows>100000 OR p_reads IS NULL OR p_reads<1 OR p_reads>4096
 OR p_program IS DISTINCT FROM kaname._authority_crud_command_plan_v3(p_intent,p_sources) THEN
  RAISE EXCEPTION 'CRUD reservation source or budget invalid' USING ERRCODE='42501';END IF;
 domain_images:=kaname._authority_crud_domain_images_v3(p_intent,p_sources,p_program,transaction_timestamp());
 journal_plan:=kaname._authority_crud_journal_plan_v3(p_intent,p_sources,domain_images);
 FOR step IN SELECT value FROM jsonb_array_elements(p_program->'commands') LOOP
  command_no:=command_no+1;command_values:=command_values||jsonb_build_object(command_no::text,'{}'::jsonb);
  IF step->>'kind' IN ('audit','binding.audit') THEN
   identifier:='evt_'||substr(replace(gen_random_uuid()::text,'-',''),1,22);
   IF audit_ids ? identifier THEN RAISE EXCEPTION 'CRUD audit random ID repeated' USING ERRCODE='P1034';END IF;
   audit_ids:=audit_ids||jsonb_build_object(identifier,true);
   command_values:=jsonb_set(command_values,ARRAY[command_no::text],jsonb_build_object('audit_id',identifier));
  ELSIF step->>'kind'='reconcile' THEN reconcile_count:=reconcile_count+1;
  ELSIF step->>'kind' IN ('fga.tuple.write','fga.tuple.delete') THEN
   SELECT count(*)::integer INTO group_count FROM (
    SELECT DISTINCT value->>'Object',value->>'User' FROM jsonb_array_elements(step->'request')
   ) actual_groups;
   counts:=counts||jsonb_build_object(command_no::text,group_count);fga_count:=fga_count+group_count;
  END IF;
 END LOOP;
 -- Порядок общей резервной части фиксирован для всех семи команд.
 -- Root/child/source tuple locks удержаны вызывающим prewait ранее.
 IF jsonb_array_length(journal_plan)>0 THEN
  SELECT * INTO STRICT part FROM kaname._authority_crud_sequence_wait_v3('resource_journal',jsonb_array_length(journal_plan),p_reads-used_reads);
  journal_ids:=part.reserved_ids;held_relations:=held_relations||part.held_relations;
  held_advisory:=held_advisory||part.held_advisory;used_reads:=used_reads+part.logical_reads;
 END IF;
 IF fga_count>0 THEN
  SELECT * INTO STRICT part FROM kaname._authority_crud_sequence_wait_v3('fga_outbox',fga_count,p_reads-used_reads);
  fga_ids:=part.reserved_ids;held_relations:=held_relations||part.held_relations;
  held_advisory:=held_advisory||part.held_advisory;used_reads:=used_reads+part.logical_reads;
 END IF;
 IF audit_ids<>'{}'::jsonb THEN
  SELECT * INTO STRICT part FROM kaname._authority_resource_audit_wait_v2(audit_ids,p_rows-used_rows,p_reads-used_reads);
  held_advisory:=held_advisory||part.lock_witness;used_reads:=used_reads+part.logical_reads;used_rows:=used_rows+part.logical_rows;
  held_relations:=held_relations||jsonb_build_array(jsonb_build_object('oid','kaname.audit_outbox'::regclass::oid,'mode','RowExclusiveLock'));
 END IF;
 IF reconcile_count>0 THEN
  SELECT * INTO STRICT part FROM kaname._authority_resource_reconcile_wait_v2(reconcile_count,p_reads-used_reads);
  reconcile_ids:=part.reserved_ids;held_relations:=held_relations||part.held_relations;
  held_advisory:=held_advisory||part.held_advisory;used_reads:=used_reads+part.logical_reads;
 END IF;
 command_no:=0;
 FOR step IN SELECT value FROM jsonb_array_elements(p_program->'commands') LOOP
  command_no:=command_no+1;
  IF step->>'kind'='reconcile' THEN
   command_values:=jsonb_set(command_values,ARRAY[command_no::text],jsonb_build_object('reconcile_id',reconcile_ids->cursor_reconcile));
   cursor_reconcile:=cursor_reconcile+1;
  ELSIF step->>'kind' IN ('fga.tuple.write','fga.tuple.delete') THEN
   group_count:=(counts->>command_no::text)::integer;
   SELECT coalesce(jsonb_agg(value ORDER BY position),'[]'::jsonb) INTO sliced
   FROM jsonb_array_elements(fga_ids) WITH ORDINALITY q(value,position)
   WHERE position>cursor_fga AND position<=cursor_fga+group_count;
   command_values:=jsonb_set(command_values,ARRAY[command_no::text],jsonb_build_object('fga_ids',sliced));
   cursor_fga:=cursor_fga+group_count;
  END IF;
 END LOOP;
 IF cursor_fga<>fga_count OR cursor_reconcile<>reconcile_count OR used_rows>p_rows OR used_reads>p_reads
 OR jsonb_array_length(held_advisory)>4096 THEN
  RAISE EXCEPTION 'CRUD reservation aggregate budget exceeded' USING ERRCODE='54000';END IF;
 RETURN jsonb_build_object('reserved',jsonb_build_object('commands',command_values,'journal_ids',journal_ids),
  'held_relations',held_relations,'held_advisory',held_advisory,'logical_rows',used_rows,'logical_reads',used_reads);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Полный persisted binding/member слой scope removal. Capture читает только
-- ordinary source строки, не принимает список ID от вызывающего как полноту.
CREATE FUNCTION kaname._authority_crud_scope_capture_v3(p_intent jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE descriptor jsonb;kind text;target_id text;rows_value jsonb;bindings jsonb:='[]'::jsonb;
 ledger jsonb:='{}'::jsonb;members jsonb:='[]'::jsonb;tables jsonb:='{}'::jsonb;table_name text;
 binding_ids text[];used_rows integer:=0;used_reads integer:=0;remaining integer;count_rows integer;
BEGIN
 descriptor:=kaname._authority_crud_intent_v3(p_intent);
 IF p_rows IS NULL OR p_rows<0 OR p_rows>100000 OR p_reads IS NULL OR p_reads<0 OR p_reads>4096 THEN
  RAISE EXCEPTION 'CRUD scope capture budget exceeded' USING ERRCODE='54000';END IF;
 IF descriptor->>'command' NOT IN ('account.delete','project.delete') THEN
  RETURN jsonb_build_object('tables',tables,'scope_bindings',bindings,'binding_ledger',ledger,
   'membership_user_ids',members,'logical_rows',0,'logical_reads',0);
 END IF;
 kind:=split_part(descriptor->>'command','.',1);target_id:=descriptor->>'id';
 IF p_reads<1 THEN RAISE EXCEPTION 'CRUD scope read budget exceeded' USING ERRCODE='54000';END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('row',row_value,'xmin',xmin_value,'ctid',ctid_value)
  ORDER BY (row_value->>'created_at')::timestamptz,row_value->>'id' COLLATE "C"),'[]'::jsonb)
 INTO rows_value FROM (
  SELECT to_jsonb(b) row_value,b.xmin::text xmin_value,b.ctid::text ctid_value FROM ONLY kaname.access_bindings b
  WHERE b.resource_type=kind AND b.resource_id=target_id
  ORDER BY b.created_at,b.id COLLATE "C" LIMIT least(p_rows+1,50001)) current_rows;
 count_rows:=jsonb_array_length(rows_value);used_reads:=1;
 IF count_rows>p_rows OR count_rows>=50000 THEN
  RAISE EXCEPTION 'CRUD complete scope exceeds capture or drain budget' USING ERRCODE='54000';END IF;
 used_rows:=count_rows;tables:=tables||jsonb_build_object('access_bindings',rows_value);
 -- Реальный ListByScope берёт created_at/id страницу 1000, потом сортирует
 -- её по ID. Нумерация здесь сохраняет те же границы страниц.
 SELECT coalesce(jsonb_agg(value->'row' ORDER BY (ordinality-1)/1000,value->'row'->>'id' COLLATE "C"),'[]'::jsonb),
  coalesce(array_agg(value->'row'->>'id' ORDER BY ordinality),ARRAY[]::text[])
 INTO bindings,binding_ids FROM jsonb_array_elements(rows_value) WITH ORDINALITY x(value,ordinality);
 FOREACH table_name IN ARRAY ARRAY['access_binding_subjects','access_binding_target_members','access_binding_emitted_tuples'] LOOP
  IF used_reads>=p_reads THEN RAISE EXCEPTION 'CRUD child read budget exceeded' USING ERRCODE='54000';END IF;
  remaining:=p_rows-used_rows;
  EXECUTE format('SELECT coalesce(jsonb_agg(jsonb_build_object(''row'',row_value,''xmin'',xmin_value,''ctid'',ctid_value) ORDER BY row_value::text COLLATE "C"),''[]''::jsonb)
   FROM (SELECT to_jsonb(t) row_value,t.xmin::text xmin_value,t.ctid::text ctid_value FROM ONLY kaname.%I t
    WHERE t.binding_id=ANY($1) ORDER BY to_jsonb(t)::text COLLATE "C" LIMIT $2) current_rows',table_name)
   INTO rows_value USING binding_ids,remaining+1;
  count_rows:=jsonb_array_length(rows_value);used_reads:=used_reads+1;
  IF count_rows>remaining THEN RAISE EXCEPTION 'CRUD child row budget exceeded' USING ERRCODE='54000';END IF;
  used_rows:=used_rows+count_rows;tables:=tables||jsonb_build_object(table_name,rows_value);
 END LOOP;
 -- Пустая ведомость каждого существующего binding записывается явно: отсутствие
 -- ключа отличается от полного пустого результата SELECT DISTINCT.
 SELECT coalesce(jsonb_object_agg(identifier,coalesce((
  SELECT jsonb_agg(jsonb_build_object('User',user_value,'Relation',relation_value,'Object',object_value)
   ORDER BY relation_value COLLATE "C",object_value COLLATE "C",user_value COLLATE "C")
  FROM (SELECT DISTINCT e->'row'->>'fga_user' user_value,e->'row'->>'relation' relation_value,e->'row'->>'object' object_value
   FROM jsonb_array_elements(tables->'access_binding_emitted_tuples') e
   WHERE e->'row'->>'binding_id'=identifier) tuples),'[]'::jsonb)),'{}'::jsonb)
 INTO ledger FROM unnest(binding_ids) identifier;
 IF kind='account' THEN
  IF used_reads>=p_reads THEN RAISE EXCEPTION 'CRUD membership read budget exceeded' USING ERRCODE='54000';END IF;
  remaining:=p_rows-used_rows;
  SELECT coalesce(jsonb_agg(jsonb_build_object('row',row_value,'xmin',xmin_value,'ctid',ctid_value) ORDER BY row_value->>'user_id' COLLATE "C"),'[]'::jsonb)
  INTO rows_value FROM (SELECT to_jsonb(m) row_value,m.xmin::text xmin_value,m.ctid::text ctid_value
   FROM ONLY kaname.memberships m WHERE m.account_id=target_id ORDER BY m.user_id COLLATE "C" LIMIT remaining+1) current_rows;
  count_rows:=jsonb_array_length(rows_value);used_reads:=used_reads+1;
  IF count_rows>remaining THEN RAISE EXCEPTION 'CRUD membership row budget exceeded' USING ERRCODE='54000';END IF;
  used_rows:=used_rows+count_rows;tables:=tables||jsonb_build_object('memberships',rows_value);
  SELECT coalesce(jsonb_agg(value->'row'->'user_id' ORDER BY value->'row'->>'user_id' COLLATE "C"),'[]'::jsonb)
  INTO members FROM jsonb_array_elements(rows_value);
 END IF;
 RETURN jsonb_build_object('tables',tables,'scope_bindings',bindings,'binding_ledger',ledger,
  'membership_user_ids',members,'logical_rows',used_rows,'logical_reads',used_reads);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Черновой фрагмент append1515; предыдущие object/Action ветви побайтово сохранены.
CREATE OR REPLACE FUNCTION kaname.authority_protocol_statement_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; manifest jsonb; allowed boolean;step jsonb;sequence_program jsonb;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NOT NULL THEN sequence_program:=kaname._authority_sequence_header_v3();END IF;
 IF sequence_program#>>'{frozen,mode}'='authorize' THEN
  RAISE EXCEPTION 'authorization-only callback cannot mutate persistent state' USING ERRCODE='42501';
 END IF;
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NOT NULL THEN
  allowed:=false;
  IF manifest->'intent'->>'kind'='object' THEN
   step:=manifest#>'{object_program,commands}'->((manifest->>'object_command')::integer-1);
   -- Проверяем только текущий выданный private command, не соседние шаги.
   -- Два закрытых UPSERT: members и fact fold команды write. Оба вызывают
   -- statement UPDATE даже без конфликтующей строки или при stale версии.
   -- Синтаксическое UPDATE подтверждает attempted INSERT того же шага;
   -- разрешённые actual row images и обязательность consumption не меняются.
   SELECT manifest->>'object_program_claimed'='true' AND EXISTS(
    SELECT 1 FROM jsonb_array_elements(manifest->'writes') w
    WHERE w->'command'=manifest->'object_command' AND w->>'table'=TG_TABLE_NAME
    AND (w->>'operation'=TG_OP OR
     (TG_OP='UPDATE' AND w->>'operation'='INSERT'
      AND ((step->>'Kind'='members' AND TG_TABLE_NAME='access_binding_target_members')
       OR (step->>'Kind'='write' AND TG_TABLE_NAME='relation_fact'))))) INTO allowed;
  ELSIF manifest->'intent'->>'kind'='crud' THEN
   -- Новый маршрут читает только текущую закрытую owner-private команду.
   -- Указание kind в caller JSON само по себе не создаёт ни proof, ни программу.
   PERFORM kaname._authority_crud_manifest_domain_v3(manifest);
   step:=manifest#>'{registration_program,commands}'->((manifest->>'object_command')::integer-1);
   allowed:=manifest->>'registration_program_claimed'='true'
    AND coalesce(step->'operations'->TG_TABLE_NAME,'[]'::jsonb) ? TG_OP;
  ELSIF manifest->'intent'->>'Action' IN ('1','2','3','4') THEN
   step:=manifest#>'{registration_program,commands}'->((manifest->>'object_command')::integer-1);
   allowed:=manifest->>'registration_program_claimed'='true'
    AND coalesce(step->'operations'->TG_TABLE_NAME,'[]'::jsonb) ? TG_OP;
  END IF;
  IF TG_OP='TRUNCATE' OR NOT coalesce(allowed,false) THEN
   RAISE EXCEPTION 'resource statement absent from current private command' USING ERRCODE='42501';
  END IF;
  RETURN NULL;
 END IF;
 proof:=kaname.authority_protocol_attestation();
 -- kaname#1034: после удаления parent каскадный child уже не обязан видеть
 -- его anchor; role target cascade также может затронуть другой account.
 -- До отдельной proven классификации adapter выбирает global ДО всех locks.
 IF proof IS NOT NULL AND proof->>'mode'<>'global'
 AND (TG_OP='TRUNCATE' OR (TG_OP='DELETE' AND TG_TABLE_NAME IN ('roles','groups','accounts'))) THEN
  RAISE EXCEPTION 'authority truncate or parent cascade requires global intent' USING ERRCODE='42501';
 END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Private storage использует существующие nonce/backend/xid и ровно тот
-- owner-owned manifest, который проверяют общие Resource row/statement guards.
CREATE FUNCTION kaname._authority_resource_crud_store_v3(p_compiled jsonb) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;descriptor jsonb;relation_id oid;field text;policy jsonb;guards jsonb;scopes jsonb;
BEGIN
 proof:=kaname.authority_protocol_attestation();descriptor:=kaname._authority_crud_intent_v3(p_compiled->'intent');
 IF proof IS NULL OR proof->>'writer_contract' IS DISTINCT FROM '2' OR proof->>'kind' IS DISTINCT FROM 'resource'
 OR proof->>'purpose' IS DISTINCT FROM 'participant' OR proof->>'consumer_abi' IS DISTINCT FROM '2'
 OR proof->>'consumer_profile' IS DISTINCT FROM 'resource_source_pending' OR proof->>'consumer_finalized' IS DISTINCT FROM 'false'
 OR current_setting('transaction_isolation')<>'read committed' OR to_regclass('pg_temp.kaname_authority_resource_manifest') IS NOT NULL
 OR (descriptor->>'global'='true' AND proof->>'mode' IS DISTINCT FROM 'global')
 OR (descriptor->>'global'='false' AND (proof->>'mode' IS DISTINCT FROM 'accounts'
  OR proof->'accounts' IS DISTINCT FROM jsonb_build_array(descriptor->>'account'))) THEN
  RAISE EXCEPTION 'CRUD private storage admission mismatch' USING ERRCODE='42501';END IF;
 FOREACH field IN ARRAY ARRAY['certificate','sources','prepared','maximum','epoch_witness','native_epochs'] LOOP
  IF jsonb_typeof(p_compiled->field) IS DISTINCT FROM 'object' THEN
   RAISE EXCEPTION 'CRUD private compiled field missing' USING ERRCODE='42501';END IF;
 END LOOP;
 FOREACH field IN ARRAY ARRAY['held_relations','held_advisory','catalog_rows'] LOOP
  IF jsonb_typeof(p_compiled->field) IS DISTINCT FROM 'array' THEN
   RAISE EXCEPTION 'CRUD private physical witness missing' USING ERRCODE='42501';END IF;
 END LOOP;
 policy:=p_compiled#>'{maximum,policy_epochs}';guards:=p_compiled#>'{maximum,source_guards}';scopes:=p_compiled#>'{maximum,binding_epochs}';
 relation_id:=kaname._authority_resource_manifest_create_v2();
 INSERT INTO pg_temp.kaname_authority_resource_manifest(
  abi,backend,transaction_id,invoker_oid,nonce,model_id,catalog_id,projector_version,mode,consumer_profile,accounts,
  intent,state,transaction_at,held_relations,held_advisory,catalog_rows,native_epochs,
  epoch_write_keys,epoch_share_keys,source_guard_write_keys,source_guard_read_keys,binding_epoch_write_scopes,binding_epoch_share_scopes,
  deferred_carrier_roles,epoch_lock_witness,writes,object_certificate,object_effects,object_sources,object_audit_reservations,
  registration_certificate,registration_sources,registration_body)
 VALUES(2,proof->>'backend',proof->>'transaction_id',(proof->>'invoker_oid')::oid,proof->>'nonce',
  proof->>'model_id',proof->>'catalog_id',proof->>'projector_version',proof->>'mode',proof->>'consumer_profile',proof->'accounts',
  p_compiled->'intent','prepared',transaction_timestamp(),
  (p_compiled->'held_relations')||jsonb_build_array(jsonb_build_object('oid',relation_id,'mode','AccessExclusiveLock')),
  p_compiled->'held_advisory',p_compiled->'catalog_rows',p_compiled->'native_epochs',
  (SELECT coalesce(jsonb_agg(key ORDER BY key COLLATE "C"),'[]'::jsonb) FROM jsonb_each_text(policy) WHERE value='write'),
  (SELECT coalesce(jsonb_agg(key ORDER BY key COLLATE "C"),'[]'::jsonb) FROM jsonb_each_text(policy) WHERE value='share'),
  (SELECT coalesce(jsonb_agg(key ORDER BY key COLLATE "C"),'[]'::jsonb) FROM jsonb_each_text(guards) WHERE value='write'),
  (SELECT coalesce(jsonb_agg(key ORDER BY key COLLATE "C"),'[]'::jsonb) FROM jsonb_each_text(guards) WHERE value='share'),
  (SELECT coalesce(jsonb_agg(key ORDER BY key COLLATE "C"),'[]'::jsonb) FROM jsonb_each_text(scopes) WHERE value='write'),
  (SELECT coalesce(jsonb_agg(key ORDER BY key COLLATE "C"),'[]'::jsonb) FROM jsonb_each_text(scopes) WHERE value='share'),
  p_compiled#>'{maximum,deferred_carrier_roles}',p_compiled->'epoch_witness','[]'::jsonb,
  '{}'::jsonb,'{}'::jsonb,'{}'::jsonb,'{}'::jsonb,
  p_compiled->'certificate',p_compiled->'sources',p_compiled->'prepared');
 PERFORM kaname._authority_resource_manifest_v2();
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Physical tuple address используется только вместе с server recapture,
-- xmin и точным OLD образом. Переезд/повторное использование ctid требует
-- restage; ctid не является новым публичным идентификатором или proof.
CREATE FUNCTION kaname._authority_crud_tuple_wait_v3(p_table text,p_captured jsonb,p_write boolean,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;captured jsonb;row_value jsonb;xmin_value text;ctid_value text;relation_id oid;
 used_rows integer:=0;used_reads integer:=0;invoker oid;lock_mode text;expected_map jsonb;physical tid[];current_row record;projection text;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'writer_contract' IS DISTINCT FROM '2' OR proof->>'kind' IS DISTINCT FROM 'resource'
 OR proof->>'consumer_profile' IS DISTINCT FROM 'resource_source_pending'
 OR proof->>'consumer_finalized' IS DISTINCT FROM 'false' OR current_setting('transaction_isolation')<>'read committed'
 OR p_table IS NULL OR p_table NOT IN ('accounts','projects','service_accounts','users','roles','groups','memberships',
  'access_bindings','access_binding_subjects','access_binding_target_members','access_binding_emitted_tuples',
  'role_rule_selectors','role_selector_verbs_pending','role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule',
  'role_grant_orphan','role_selector_prune','service_account_oauth_clients','relation_fact','resource_registration_pointer',
  'resource_registration_retirement','cluster_admin_grants','clusters','own_ceilings','account_admission_rate_limits')
 OR jsonb_typeof(p_captured) IS DISTINCT FROM 'array' OR p_write IS NULL
 OR p_rows IS NULL OR p_rows<0 OR p_rows>100000 OR p_reads IS NULL OR p_reads<0 OR p_reads>4096 THEN
  RAISE EXCEPTION 'invalid CRUD tuple prewait' USING ERRCODE='42501';END IF;
 IF jsonb_array_length(p_captured)>p_rows OR 2>p_reads THEN
  RAISE EXCEPTION 'CRUD tuple wait budget exceeded' USING ERRCODE='54000';END IF;
 invoker:=(proof->>'invoker_oid')::oid;relation_id:=to_regclass(format('kaname.%I',p_table));
 IF relation_id IS NULL OR NOT has_table_privilege(invoker,relation_id,'SELECT')
 OR NOT has_any_column_privilege(invoker,relation_id,'UPDATE')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_inherits WHERE inhparent=relation_id OR inhrelid=relation_id) THEN
  RAISE EXCEPTION 'CRUD tuple prewait caller privilege or relation mismatch' USING ERRCODE='42501';END IF;
 -- Table admission предшествует tuple wait; отсутствующий row не является
 -- оправданием пропустить relation lock перед queued TRUNCATE.
 lock_mode:=CASE WHEN p_write THEN 'ROW EXCLUSIVE' ELSE 'ROW SHARE' END;
 EXECUTE format('LOCK TABLE ONLY kaname.%I IN %s MODE',p_table,lock_mode);used_reads:=1;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(p_captured) value WHERE jsonb_typeof(value->'row') IS DISTINCT FROM 'object'
  OR value->>'xmin' IS NULL OR value->>'ctid' IS NULL)
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(p_captured) value GROUP BY value->>'ctid' HAVING count(*)<>1) THEN
  RAISE EXCEPTION 'CRUD physical source address missing or repeated' USING ERRCODE='42501';END IF;
 SELECT coalesce(jsonb_object_agg(value->>'ctid',value),'{}'::jsonb),
  coalesce(array_agg((value->>'ctid')::tid ORDER BY (value->>'ctid')::tid),ARRAY[]::tid[])
 INTO expected_map,physical FROM jsonb_array_elements(p_captured) value;
 -- Один bounded read на таблицу: не N независимых SELECT для N строк.
 projection:=CASE WHEN p_table='service_account_oauth_clients' THEN 'jsonb_build_object(''id'',t.id,''sva_id'',t.sva_id)' ELSE 'to_jsonb(t)' END;
 FOR current_row IN EXECUTE format('SELECT %s row_value,t.xmin::text xmin_value,t.ctid::text ctid_value
  FROM ONLY kaname.%I t WHERE t.ctid=ANY($1::tid[]) ORDER BY t.ctid FOR %s',projection,p_table,
  CASE WHEN p_write THEN 'UPDATE' ELSE 'SHARE' END) USING physical LOOP
  used_rows:=used_rows+1;captured:=expected_map->current_row.ctid_value;
  IF captured IS NULL OR current_row.xmin_value IS DISTINCT FROM captured->>'xmin'
  OR NOT current_row.row_value @> (captured->'row') THEN
   RAISE EXCEPTION 'CRUD physical source changed before final clock' USING ERRCODE='P1034';END IF;
 END LOOP;
 used_reads:=used_reads+1;
 IF used_rows<>jsonb_array_length(p_captured) THEN
  RAISE EXCEPTION 'CRUD physical source moved before final clock' USING ERRCODE='P1034';END IF;

 RETURN jsonb_build_object('logical_rows',used_rows,'logical_reads',used_reads,
  'held_relations',jsonb_build_array(jsonb_build_object('oid',relation_id,'mode',CASE WHEN p_write THEN 'RowExclusiveLock' ELSE 'RowShareLock' END)));
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Только owner compiler вызывает этот primitive с уже выведенным конечным
-- набором ключей. Caller не получает EXECUTE и не задаёт SQL predicate.
CREATE FUNCTION kaname._authority_crud_unique_wait_v3(p_table text,p_keys jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(current_rows jsonb,held_relations jsonb,held_advisory jsonb,logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;table_id oid;predicate text;item record;key_value jsonb;canonical text;
 actual jsonb;xmin_value text;found_rows jsonb:='[]'::jsonb;held jsonb:='[]'::jsonb;keys jsonb:='{}'::jsonb;
 used_rows integer:=0;used_reads integer:=1;invoker oid;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'writer_contract' IS DISTINCT FROM '2'
 OR proof->>'kind' IS DISTINCT FROM 'resource' OR proof->>'purpose' IS DISTINCT FROM 'participant'
 OR proof->>'consumer_abi' IS DISTINCT FROM '2'
 OR proof->>'consumer_profile' IS DISTINCT FROM 'resource_source_pending'
 OR proof->>'consumer_finalized' IS DISTINCT FROM 'false'
 OR current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'CRUD key prewait requires pending full RC' USING ERRCODE='42501';END IF;
 IF jsonb_typeof(p_keys) IS DISTINCT FROM 'array' OR jsonb_array_length(p_keys)>100000
 OR p_rows IS NULL OR p_rows<0 OR p_rows>100000 OR p_reads IS NULL OR p_reads<1 OR p_reads>4096 THEN
  RAISE EXCEPTION 'CRUD key prewait budget exceeded' USING ERRCODE='54000';END IF;
 CASE p_table
 WHEN 'accounts','projects','service_accounts','issued_account_ids' THEN predicate:='t.id=$1->>''id''';
 WHEN 'project_resource_quotas' THEN predicate:='t.carrier_type=$1->>''carrier_type'' AND t.carrier_id=$1->>''carrier_id'' AND t.kind=$1->>''kind''';
 WHEN 'identity_admission_windows' THEN predicate:='t.carrier_id=$1->>''carrier_id'' AND t.kind=$1->>''kind''';
 ELSE RAISE EXCEPTION 'unsupported CRUD key wait table' USING ERRCODE='42501';
 END CASE;
 table_id:=to_regclass('kaname.'||p_table);invoker:=(proof->>'invoker_oid')::oid;
 IF table_id IS NULL OR EXISTS(SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid=table_id OR inhparent=table_id)
 OR NOT has_table_privilege(invoker,table_id,'SELECT') OR NOT has_any_column_privilege(invoker,table_id,'UPDATE') THEN
  RAISE EXCEPTION 'CRUD physical row wait requires existing caller ACL and exact table' USING ERRCODE='42501';END IF;
 FOR key_value IN SELECT value FROM jsonb_array_elements(p_keys) LOOP
  canonical:=kaname._authority_crud_unique_key_v3(p_table,key_value);
  IF keys ? canonical AND keys->canonical IS DISTINCT FROM key_value THEN
   RAISE EXCEPTION 'CRUD same unique key has inconsistent descriptor' USING ERRCODE='42501';END IF;
  keys:=keys||jsonb_build_object(canonical,key_value);
 END LOOP;
 IF (SELECT count(*) FROM jsonb_object_keys(keys))+1>p_reads THEN
  RAISE EXCEPTION 'CRUD key read reservation exceeds budget' USING ERRCODE='54000';END IF;
 -- Порядок RX→key совпадает с настоящим INSERT, включая очередь TRUNCATE.
 -- Порядок МЕЖДУ таблицами задаёт общий compiler по фактическому trigger graph;
 -- этот primitive не захватывает соседние root/child таблицы самовольно.
 EXECUTE format('LOCK TABLE ONLY kaname.%I IN ROW EXCLUSIVE MODE',p_table);
 FOR item IN SELECT DISTINCT hashtext(key) hashed FROM jsonb_object_keys(keys) key ORDER BY hashed LOOP
  PERFORM pg_advisory_xact_lock(1262569303,item.hashed);
  held:=held||jsonb_build_array(jsonb_build_object('classid',1262569303,'objid',(item.hashed::bigint & 4294967295),
   'objsubid',2,'mode','ExclusiveLock'));
 END LOOP;
 FOR item IN SELECT key,value FROM jsonb_each(keys) ORDER BY key COLLATE "C" LOOP
  actual:=NULL;xmin_value:=NULL;
  EXECUTE format('SELECT to_jsonb(t),t.xmin::text FROM ONLY kaname.%I t WHERE %s FOR UPDATE',p_table,predicate)
   INTO actual,xmin_value USING item.value;
  used_reads:=used_reads+1;
  IF actual IS NOT NULL THEN
   used_rows:=used_rows+1;
   IF used_rows>p_rows THEN RAISE EXCEPTION 'CRUD key row budget exceeded' USING ERRCODE='54000';END IF;
  END IF;
  found_rows:=found_rows||jsonb_build_array(jsonb_build_object('key',item.key,'row',actual,'xmin',xmin_value));
 END LOOP;
 RETURN QUERY SELECT found_rows,jsonb_build_array(jsonb_build_object('oid',table_id,'mode','RowExclusiveLock')),
  held,used_rows,used_reads;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Метаданные producer выводятся из exact images и private captured graph.
-- Typed epoch/source guards не подменяются одним глобальным wildcard.
CREATE FUNCTION kaname._authority_crud_json_keys_v3(p_map jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT coalesce(jsonb_agg(k ORDER BY k COLLATE "C"),'[]'::jsonb) FROM jsonb_object_keys(p_map) k
$$;

CREATE FUNCTION kaname._authority_crud_write_metadata_v3(p_intent jsonb,p_index jsonb,p_image jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE descriptor jsonb;row_value jsonb;carrier jsonb;role_row jsonb;subject jsonb;table_name text;account_id text;
 binding_id text;role_id text;actor_key text;scope_key text;group_id text;object_key text;model_type text;dotted text;
 policy jsonb:='{}';shared jsonb:=jsonb_build_object('*',true);guards jsonb:='{}';scopes jsonb:='{}';deferred jsonb:='{}';
 class_name text:='source';operation text;coordinate text;known_account text;
BEGIN
 descriptor:=kaname._authority_crud_intent_v3(p_intent);table_name:=p_image->>'table';operation:=p_image->>'operation';
 IF p_index->'descriptor' IS DISTINCT FROM descriptor OR operation NOT IN ('INSERT','UPDATE','DELETE')
 OR jsonb_typeof(p_image->'required') IS DISTINCT FROM 'boolean' THEN
  RAISE EXCEPTION 'invalid CRUD image metadata input' USING ERRCODE='42501';END IF;
 FOR row_value IN SELECT value FROM jsonb_array_elements(jsonb_build_array(p_image->'old',p_image->'new'))
  WHERE value<>'null'::jsonb LOOP
  account_id:=NULL;binding_id:=NULL;role_id:=NULL;actor_key:=NULL;group_id:=NULL;
  CASE table_name
  WHEN 'accounts' THEN
   account_id:=row_value->>'id';policy:=policy||jsonb_build_object('user:'||(row_value->>'owner_user_id'),true,
    'scope:'||account_id,true,'scope:account:'||account_id,true);
  WHEN 'projects' THEN
   account_id:=row_value->>'account_id';policy:=policy||jsonb_build_object('scope:'||account_id,true,'scope:account:'||account_id,true);
   IF operation='DELETE' THEN policy:=policy||jsonb_build_object('*',true);END IF;
  WHEN 'users' THEN
   policy:=policy||jsonb_build_object('user:'||(row_value->>'id'),true);
   -- account SET NULL меняет identity OLD owner; global classification
   -- заранее выбрана родительским снятием аккаунта.
   IF operation='UPDATE' AND p_image->'old'->'account_id' IS DISTINCT FROM p_image->'new'->'account_id' THEN
    policy:=policy||jsonb_build_object('*',true);END IF;
  WHEN 'service_accounts' THEN
   account_id:=row_value->>'account_id';policy:=policy||jsonb_build_object('service_account:'||(row_value->>'id'),true);
   IF coalesce(row_value->>'created_by_id','')<>'' THEN
    policy:=policy||jsonb_build_object((row_value->>'created_by_type')||':'||(row_value->>'created_by_id'),true);END IF;
  WHEN 'memberships' THEN
   account_id:=row_value->>'account_id';policy:=policy||jsonb_build_object('user:'||(row_value->>'user_id'),true);
  WHEN 'roles' THEN
   role_id:=row_value->>'id';account_id:=nullif(row_value->>'account_id','');
   IF account_id IS NULL THEN account_id:=p_index#>>ARRAY['projects',coalesce(row_value->>'project_id',''),'account_id'];END IF;
   guards:=guards||jsonb_build_object('role:'||role_id,true);
   policy:=policy||jsonb_build_object('role:'||role_id,true,'carriers:role:'||role_id,true,'carrier_latch:role:'||role_id,true);
  WHEN 'role_rule_selectors','role_selector_verbs_pending','role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule' THEN
   role_id:=row_value->>'role_id';role_row:=p_index#>ARRAY['roles',role_id];
   IF jsonb_typeof(role_row) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'CRUD role owner metadata omitted' USING ERRCODE='42501';END IF;
   account_id:=nullif(role_row->>'account_id','');
   IF account_id IS NULL THEN account_id:=p_index#>>ARRAY['projects',coalesce(role_row->>'project_id',''),'account_id'];END IF;
   guards:=guards||jsonb_build_object('role:'||role_id,true);policy:=policy||jsonb_build_object('role:'||role_id,true);
   IF table_name='role_rule_selectors' AND (row_value->>'arm' IS DISTINCT FROM 'anchor' OR row_value->>'container_type' IS NOT NULL) THEN account_id:=NULL;END IF;
  WHEN 'access_bindings','access_binding_subjects','access_binding_target_members','access_binding_emitted_tuples' THEN
   binding_id:=CASE WHEN table_name='access_bindings' THEN row_value->>'id' ELSE row_value->>'binding_id' END;
   carrier:=CASE WHEN table_name='access_bindings' THEN row_value ELSE p_index#>ARRAY['bindings',binding_id] END;
   IF jsonb_typeof(carrier) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'CRUD binding owner metadata omitted' USING ERRCODE='42501';END IF;
   guards:=guards||jsonb_build_object('binding:'||binding_id,true);role_id:=carrier->>'role_id';
   account_id:=CASE WHEN carrier->>'resource_type'='account' THEN carrier->>'resource_id'
    WHEN carrier->>'resource_type'='project' THEN p_index#>>ARRAY['projects',carrier->>'resource_id','account_id'] END;
   IF coalesce(p_index->'broad_roles' ? role_id,false) THEN account_id:=NULL;END IF;
   IF table_name='access_binding_target_members' AND row_value->>'object_type'='iam.group' THEN group_id:=row_value->>'object_id';
   ELSIF table_name='access_binding_emitted_tuples' AND row_value->>'member_object_type'='iam.group' THEN group_id:=row_value->>'member_object_id';
   ELSIF table_name='access_binding_emitted_tuples' AND row_value->>'object' LIKE 'iam_group:%' THEN group_id:=substr(row_value->>'object',11);END IF;
   IF group_id IS NOT NULL AND p_index#>>ARRAY['groups',group_id,'account_id'] IS DISTINCT FROM account_id THEN account_id:=NULL;END IF;
   IF table_name IN ('access_bindings','access_binding_subjects') THEN
    FOR subject IN SELECT value FROM jsonb_array_elements(jsonb_build_array(jsonb_build_object('subject_type',carrier->>'subject_type',
     'subject_id',carrier->>'subject_id'))||coalesce(p_index#>ARRAY['subjects',binding_id],'[]'::jsonb)) LOOP
     actor_key:=CASE WHEN subject->>'subject_id'='*' OR subject->>'subject_type'='system_class' THEN '*'
      ELSE (subject->>'subject_type')||':'||(subject->>'subject_id') END;
     IF actor_key IS NULL OR actor_key LIKE '%:' THEN RAISE EXCEPTION 'CRUD source subject missing' USING ERRCODE='42501';END IF;
     policy:=policy||jsonb_build_object(actor_key,true);
    END LOOP;
    IF coalesce(role_id,'')<>'' THEN
     shared:=shared||jsonb_build_object('carrier_latch:role:'||role_id,true);
     policy:=policy||jsonb_build_object('carriers:role:'||role_id,true);deferred:=deferred||jsonb_build_object(role_id,true);
    END IF;
   END IF;
  WHEN 'relation_fact','fga_outbox' THEN
   IF table_name='relation_fact' THEN
    model_type:=row_value->>'object_type';coordinate:=model_type||':'||(row_value->>'object_id');
   ELSE coordinate:=row_value#>>'{payload,object}';model_type:=split_part(coordinate,':',1);END IF;
   known_account:=p_index->'object_accounts'->>coordinate;
   IF descriptor->>'command'='project.create' THEN
    IF coordinate IS DISTINCT FROM 'project:'||(descriptor->>'id') OR known_account IS DISTINCT FROM descriptor->>'account' THEN
     RAISE EXCEPTION 'local ProjectCreate structural effect escaped NEW coordinate' USING ERRCODE='42501';END IF;
    class_name:='output';object_key:=jsonb_build_array('iam.project',descriptor->>'id')::text;
    policy:=policy||jsonb_build_object('object:'||object_key,true,'scope:account:'||known_account,true);
    account_id:=known_account;
   ELSE
    IF coalesce(known_account,'')<>'' THEN
     policy:=policy||jsonb_build_object('scope:'||known_account,true,'scope:account:'||known_account,true);account_id:=known_account;
    ELSE policy:=policy||jsonb_build_object('*',true);END IF;
    IF table_name='relation_fact' THEN
     actor_key:=row_value->>'subject';
     IF actor_key ~ '^(user|service_account):[^#*]+$' THEN policy:=policy||jsonb_build_object(actor_key,true);
     ELSIF actor_key ~ '^(group|iam_group):[^#*]+#member$' THEN
      policy:=policy||jsonb_build_object('group:'||split_part(split_part(actor_key,':',2),'#',1),true);
     ELSIF actor_key !~ '^(account|project|cluster):[^#*]+$' THEN policy:=policy||jsonb_build_object('*',true);END IF;
    END IF;
   END IF;
  ELSE RAISE EXCEPTION 'CRUD authority table not classified' USING ERRCODE='42501';
  END CASE;
  -- Только таблицы с binding epoch triggers получают эти obligations.
  IF table_name IN ('accounts','projects','service_accounts','users','memberships','roles','role_rule_selectors','role_selector_verbs_pending',
   'role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule','access_bindings','access_binding_subjects',
   'access_binding_target_members','access_binding_emitted_tuples','relation_fact','fga_outbox') THEN
   scopes:=scopes||jsonb_build_object(coalesce(account_id,''),true);
  END IF;
 END LOOP;
 IF descriptor->>'global'='false' AND (policy ? '*' OR scopes ? '') THEN
  RAISE EXCEPTION 'CRUD local effect requires unannounced global scope' USING ERRCODE='P1034';END IF;
 RETURN jsonb_build_object('class',class_name,'epoch_write_keys',kaname._authority_crud_json_keys_v3(policy),
  'epoch_share_keys',kaname._authority_crud_json_keys_v3(shared),'source_guard_write_keys',kaname._authority_crud_json_keys_v3(guards),
  'source_guard_read_keys','[]'::jsonb,'binding_epoch_write_scopes',kaname._authority_crud_json_keys_v3(scopes),
  'binding_epoch_share_scopes','[""]'::jsonb,'deferred_carrier_roles',kaname._authority_crud_json_keys_v3(deferred));
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Один свежий signed lockset snapshot; прежние proof/consumer проверки и порядок отказов сохранены.
CREATE FUNCTION kaname._authority_protocol_snapshot_v3()
RETURNS TABLE(proof jsonb,compatibility_shared boolean,compatibility_exclusive boolean,population_oid oid,
 population_shared boolean,population_row_exclusive boolean,population_extra_shared boolean,population_extra_row_exclusive boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE temp_oid oid; current_invoker oid; strict_mode boolean; expected_mode text; root_present boolean; accounts_present boolean; database_oid oid;
BEGIN
 -- Unsigned RR сохраняет locking freshness прежнего протокола. Signed RC
 -- использует только private witness, созданный после successful protocol/identity
 -- FOR SHARE в entry: повторное acquisition после final clock запрещено.
 temp_oid:=to_regclass('pg_temp.kaname_authority_attestation');
 IF temp_oid IS NULL THEN
  SELECT enforcement='strict' INTO STRICT strict_mode FROM kaname.authority_writer_protocol WHERE singleton FOR SHARE;
  IF NOT strict_mode THEN RETURN NEXT;RETURN; END IF;
  RAISE EXCEPTION 'authority transaction attestation required' USING ERRCODE='42501';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=temp_oid AND relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) AND relpersistence='t' AND relkind='r') THEN
  RAISE EXCEPTION 'untrusted authority attestation storage' USING ERRCODE='42501';
 END IF;
 SELECT to_jsonb(a) INTO proof FROM pg_temp.kaname_authority_attestation a;
 IF proof IS NULL THEN
  SELECT enforcement='strict' INTO STRICT strict_mode FROM kaname.authority_writer_protocol WHERE singleton FOR SHARE;
  IF NOT strict_mode THEN RETURN NEXT;RETURN; END IF;
  RAISE EXCEPTION 'authority transaction attestation required' USING ERRCODE='42501';
 END IF;
 SELECT oid INTO STRICT current_invoker FROM pg_catalog.pg_roles WHERE rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
 -- Ряд witness записан тем же entry после получения обоих row locks.
 -- SAVEPOINT rollback, отменяющий их acquisition, отменяет и INSERT witness;
 -- старый witness не проходит xid/backend/nonce и ON COMMIT DELETE ROWS.
 IF current_setting('transaction_isolation')<>'read committed'
 OR (proof->>'backend')::integer<>pg_backend_pid()
 OR (proof->>'transaction_id')::xid8 IS DISTINCT FROM pg_current_xact_id_if_assigned()
 OR (proof->>'invoker_oid')::oid<>current_invoker OR proof->>'nonce' IS NULL
 OR NOT EXISTS(SELECT 1 FROM kaname.authority_writer_contract c WHERE c.singleton AND c.required_contract=(proof->>'writer_contract')::integer)
 OR NOT EXISTS(SELECT 1 FROM kaname.authority_semantic_identity a,kaname.authority_writer_protocol p WHERE a.singleton AND p.singleton AND ((proof->>'purpose' IN ('transition','participant') AND p.enforcement='compatibility' AND a.phase='prepared') OR (proof->>'purpose' IN ('decision','participant') AND p.enforcement='strict' AND a.phase='active')) AND a.protocol_version=(proof->>'protocol')::integer AND p.protocol_version=a.protocol_version AND a.model_id=proof->>'model_id' AND a.catalog_id=proof->>'catalog_id' AND a.projector_version=proof->>'projector_version') THEN
  RAISE EXCEPTION 'authority transaction attestation mismatch' USING ERRCODE='42501';
 END IF;
 expected_mode:=CASE WHEN proof->>'mode'='global' THEN 'ExclusiveLock' ELSE 'ShareLock' END;
 SELECT d.oid INTO database_oid FROM pg_catalog.pg_database d WHERE d.datname=current_database();
 -- Без ::regclass: отсутствующий latch не должен опередить root/consumer/compat отказ.
 -- Public wrapper сохранит позднее обязательное разрешение исходного regclass.
 SELECT c.oid INTO population_oid FROM pg_catalog.pg_class c
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='kaname' AND c.relname='authority_producer_population_latch';
 -- Один свежий snapshot только этой invocation. Relation extra-modes намеренно
 -- не ограничены database: это точная прежняя семантика второго latch EXISTS.
 WITH held AS MATERIALIZED (
  SELECT l.locktype,l.database,l.classid,l.objid,l.mode,l.relation
  FROM pg_catalog.pg_locks l
  WHERE l.pid=pg_backend_pid() AND l.granted
   AND ((l.locktype='advisory' AND l.objsubid=2
     AND l.classid IN (1262569283::oid,1262569281::oid,1262569292::oid))
    OR (l.locktype='relation' AND l.relation=population_oid))
 ), lock_flags AS (
  -- Один проход по свежему held для root и фиксированных flags. COALESCE
  -- сохраняет EXISTS-семантику: пустой набор/только NULL predicates дают false.
  -- Account EXCEPT ниже остаётся отдельным и вычисляется только после root.
  SELECT coalesce(bool_or(h.database=database_oid AND h.locktype='advisory'
    AND h.classid=1262569283::oid AND h.objid=0::oid AND h.mode=expected_mode),false) AS root_held,
   coalesce(bool_or(h.database=database_oid AND h.locktype='advisory'
    AND h.classid=1262569292::oid AND h.objid=0::oid AND h.mode='ShareLock'),false) AS compatibility_shared_held,
   coalesce(bool_or(h.database=database_oid AND h.locktype='advisory'
    AND h.classid=1262569292::oid AND h.objid=0::oid AND h.mode='ExclusiveLock'),false) AS compatibility_exclusive_held,
   coalesce(bool_or(h.database=database_oid AND h.locktype='relation'
    AND h.relation=population_oid AND h.mode='ShareLock'),false) AS population_shared_held,
   coalesce(bool_or(h.database=database_oid AND h.locktype='relation'
    AND h.relation=population_oid AND h.mode='RowExclusiveLock'),false) AS population_row_exclusive_held,
   coalesce(bool_or(h.locktype='relation' AND h.relation=population_oid
    AND h.mode<>'ShareLock' AND h.mode<>'AccessShareLock'),false) AS population_extra_shared_held,
   coalesce(bool_or(h.locktype='relation' AND h.relation=population_oid
    AND h.mode<>'RowExclusiveLock' AND h.mode<>'AccessShareLock'),false) AS population_extra_row_exclusive_held
  FROM held h
 )
 SELECT r.root_held,
  CASE WHEN r.root_held AND proof->>'mode'='accounts' THEN
   NOT EXISTS (
    SELECT DISTINCT (hashtext(value)::bigint & 4294967295)::oid
     FROM jsonb_array_elements_text(proof->'accounts')
    EXCEPT
    SELECT h.objid FROM held h WHERE h.database=database_oid AND h.locktype='advisory'
     AND h.classid=1262569281::oid AND h.mode='ExclusiveLock'
   )
  ELSE true END,
  r.compatibility_shared_held,r.compatibility_exclusive_held,
  r.population_shared_held,r.population_row_exclusive_held,
  r.population_extra_shared_held,r.population_extra_row_exclusive_held
 INTO root_present,accounts_present,compatibility_shared,compatibility_exclusive,
  population_shared,population_row_exclusive,population_extra_shared,population_extra_row_exclusive
 FROM lock_flags r;
 -- Сначала тот же root отказ; malformed accounts не вычисляются до него.
 IF NOT root_present THEN
  RAISE EXCEPTION 'authority cluster barrier missing' USING ERRCODE='42501';
 END IF;
 IF NOT accounts_present THEN
  RAISE EXCEPTION 'authority account barrier missing' USING ERRCODE='42501';
 END IF;
 RETURN NEXT;
END $$;
CREATE OR REPLACE FUNCTION kaname._authority_protocol_attestation_v1_body() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;
BEGIN
 -- Прежний owner-only ABI возвращает только proof, без consumer-проверок/flags.
 SELECT s.proof INTO STRICT proof FROM kaname._authority_protocol_snapshot_v3() s;
 RETURN proof;
END $$;
CREATE OR REPLACE FUNCTION kaname.authority_protocol_attestation() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; consumer jsonb; storage oid; lock_mode text; snapshot record;
BEGIN
 -- Невалидная signed attestation здесь бросает ошибку; unsigned fallback нет.
 SELECT s.* INTO STRICT snapshot FROM kaname._authority_protocol_snapshot_v3() s;
 proof:=snapshot.proof;
 IF proof IS NULL THEN
  PERFORM kaname._authority_compare_legacy_write_allowed_v2();
  -- Compatibility RR/direct/maintenance writer должен войти до первой DML
  -- через общий BEFORE STATEMENT guard. Это единственная unsigned ветка.
  PERFORM pg_advisory_xact_lock(1262569292,0);
  RETURN NULL;
 END IF;
 storage:=to_regclass('pg_temp.kaname_authority_consumer');
 IF storage IS NULL OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=storage
  AND relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)
  AND relpersistence='t' AND relkind='r') THEN
  RAISE EXCEPTION 'authority consumer v2 witness missing' USING ERRCODE='42501';
 END IF;
 SELECT to_jsonb(c) INTO consumer FROM pg_temp.kaname_authority_consumer c;
 IF consumer IS NULL OR consumer->>'abi' IS DISTINCT FROM '2'
 OR consumer->>'backend' IS DISTINCT FROM proof->>'backend'
 OR consumer->>'transaction_id' IS DISTINCT FROM proof->>'transaction_id'
 OR consumer->>'invoker_oid' IS DISTINCT FROM proof->>'invoker_oid'
 OR consumer->>'nonce' IS DISTINCT FROM proof->>'nonce'
 OR consumer->>'profile' NOT IN ('typed','full','resource_pending','resource_source_pending') THEN
  RAISE EXCEPTION 'authority consumer v2 witness mismatch' USING ERRCODE='42501';
 END IF;
 lock_mode:=CASE WHEN proof->>'mode'='global' THEN 'ExclusiveLock' ELSE 'ShareLock' END;
 IF NOT (CASE WHEN lock_mode='ExclusiveLock' THEN snapshot.compatibility_exclusive ELSE snapshot.compatibility_shared END) THEN
  RAISE EXCEPTION 'authority compatibility admission missing' USING ERRCODE='42501';
 END IF;
 IF consumer->>'profile' IN ('typed','full','resource_pending','resource_source_pending') THEN
  lock_mode:=CASE WHEN consumer->>'profile' IN ('typed','full') THEN 'ShareLock' ELSE 'RowExclusiveLock' END;
  -- Позднее разрешение regclass сохраняет прежний 42P01 после consumer/compat.
  -- OID привязывает flags к тому же объекту, а не к вновь созданному одноимённому.
  IF snapshot.population_oid IS DISTINCT FROM 'kaname.authority_producer_population_latch'::regclass::oid
  OR (CASE WHEN lock_mode='ShareLock' THEN NOT snapshot.population_shared OR snapshot.population_extra_shared
   ELSE NOT snapshot.population_row_exclusive OR snapshot.population_extra_row_exclusive END) THEN
   RAISE EXCEPTION 'authority population latch mode mismatch' USING ERRCODE='42501';
  END IF;
 END IF;
 RETURN proof||jsonb_build_object('consumer_abi',2,'consumer_profile',consumer->>'profile','consumer_finalized',consumer->'finalized');
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_grant_mutation_preflight(p_profile text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; sequence_id regclass;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR coalesce(proof->>'mode','') NOT IN ('accounts','global') THEN
  RAISE EXCEPTION 'grant mutation requires signed coordinator entry' USING ERRCODE='42501';
 END IF;
 IF NOT coalesce(
   (p_profile='binding' AND proof->>'kind'='binding' AND proof->>'purpose' IN ('decision','participant'))
   OR (p_profile='withdrawal' AND proof->>'kind' IN ('binding','delegation') AND proof->>'purpose'='participant')
   OR (p_profile='delegation' AND proof->>'kind'='delegation' AND proof->>'purpose'='participant'),false) THEN
  RAISE EXCEPTION 'grant mutation profile does not match signed entry' USING ERRCODE='42501';
 END IF;
 IF p_profile='delegation' THEN
  LOCK TABLE kaname.audit_outbox,kaname.authority_binding_epoch,
   kaname.authority_policy_epoch,kaname.grant_delegations IN ROW EXCLUSIVE MODE;
 ELSE
  -- Закрытое объединение: родитель/состав, синхронная свёртка, журналы
  -- событий, эпохи policy/binding и отложенные метаданные носителей. Отзыв GD
  -- добавляет настоящего родителя, не подменяет подписанный kind на Binding.
  LOCK TABLE kaname.access_binding_emitted_tuples,kaname.access_binding_subjects,
   kaname.access_binding_target_members,kaname.access_bindings,kaname.audit_outbox,
   kaname.authority_binding_epoch,kaname.authority_policy_carrier_pending,
   kaname.authority_policy_epoch,kaname.fga_outbox,kaname.relation_fact,
   kaname.resource_journal,kaname.resource_reconcile_outbox,
   kaname.subject_change_outbox IN ROW EXCLUSIVE MODE;
  IF proof->>'kind'='delegation' THEN
   LOCK TABLE kaname.grant_delegations IN ROW EXCLUSIVE MODE;
  END IF;
  -- nextval держит RowExclusiveLock последовательности до конца TX (PG16).
  -- Допустимы пропуски ID, как при откате; бизнес-строки до проверки не меняются.
  FOREACH sequence_id IN ARRAY ARRAY[
   'kaname.resource_reconcile_outbox_id_seq'::regclass,
   'kaname.subject_change_outbox_id_seq'::regclass
  ] LOOP
   IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_catalog.pg_backend_pid()
    AND l.locktype='relation' AND l.relation=sequence_id
    AND l.mode='RowExclusiveLock' AND l.granted) THEN
    PERFORM pg_catalog.nextval(sequence_id);
   END IF;
  END LOOP;
 END IF;
 IF p_profile IN ('binding','withdrawal') THEN PERFORM kaname._authority_sequence_expect_v3('binding');END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Точные входы CREATE/metadata и отдельная авторизация без эффекта.
-- Ни один вызов не принимает кортежи, journal program или reserved IDs клиента.
CREATE FUNCTION kaname._authority_binding_scope_tier_v3(p_scope text,p_rules jsonb,p_permissions jsonb)
RETURNS text LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE permissions jsonb:=p_permissions;covering jsonb;permission text;verb text;strength integer:=0;result text;
BEGIN
 IF jsonb_typeof(p_rules) IS DISTINCT FROM 'array' OR jsonb_typeof(p_permissions) IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'binding role projection is not closed' USING ERRCODE='42501';END IF;
 IF jsonb_array_length(p_rules)>0 OR jsonb_array_length(p_permissions)=0 OR coalesce(p_scope,'')='' THEN RETURN NULL;END IF;
 IF lower(p_scope)='account' THEN
  SELECT coalesce(jsonb_agg(value),'[]') INTO covering FROM jsonb_array_elements_text(p_permissions)
  WHERE split_part(value,'.',1) IN ('*','iam') AND split_part(value,'.',2) IN ('*','account');
  IF jsonb_array_length(covering)>0 THEN permissions:=covering;END IF;
 END IF;
 FOR permission IN SELECT value FROM jsonb_array_elements_text(permissions) LOOP
  verb:=lower(regexp_replace(permission,'^.*\.',''));
  IF verb IN ('*','admin','manage') THEN strength:=greatest(strength,3);
  ELSIF verb IN ('create','update','delete','write','patch','put','editor','edit','start','stop','move',
   'addtargets','removetargets','attachtargetgroup','detachtargetgroup','enablezones','disablezones','addlistener','removelistener')
   THEN strength:=greatest(strength,2);
  END IF;
 END LOOP;
 result:=CASE WHEN strength=3 THEN 'admin' WHEN strength=2 THEN 'editor' ELSE 'viewer' END;
 IF lower(p_scope)='account' AND jsonb_array_length(covering)=0 AND result='admin' THEN result:='editor';END IF;
 IF lower(p_scope)='cluster' THEN result:=CASE WHEN result='viewer' THEN 'system_viewer' ELSE 'system_admin' END;END IF;
 RETURN result;
END $$;

CREATE FUNCTION kaname._authority_binding_journal_v3(p_table text,p_operation text,p_old jsonb,p_new jsonb,p_owner jsonb,p_ordinal integer)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE origin jsonb;row_value jsonb;
BEGIN
 IF p_table NOT IN ('access_bindings','access_binding_subjects') OR p_operation NOT IN ('INSERT','UPDATE','DELETE')
 OR p_owner->>'id' IS NULL OR p_ordinal<1 THEN RAISE EXCEPTION 'invalid binding journal source' USING ERRCODE='42501';END IF;
 origin:=jsonb_build_object('table',p_table,'operation',p_operation,
  'when',CASE WHEN p_table='access_bindings' AND p_operation='DELETE' THEN 'BEFORE' ELSE 'AFTER' END,'old',p_old,'new',p_new);
 row_value:=jsonb_build_object('resource_kind','iam_access_binding','resource_id',p_owner->>'id',
  'project_id',kaname.resource_journal_project('iam_access_binding',p_owner),
  'scope',kaname.resource_journal_scope('iam_access_binding',p_owner),
  'event_type',CASE WHEN p_table='access_binding_subjects' OR p_operation='UPDATE' THEN 'UPDATED'
   WHEN p_operation='INSERT' THEN 'CREATED' ELSE 'DELETED' END,
  'payload',jsonb_build_object('id',p_owner->>'id'));
 RETURN jsonb_build_object('table','resource_journal','origin',origin,'ordinal',p_ordinal,'row',row_value,'stamp','transaction');
END $$;

CREATE FUNCTION kaname.authority_binding_sequence_prepare_v3(p_mode text,p_input jsonb)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;parent jsonb;next_parent jsonb;source_row jsonb;role_row jsonb;subjects jsonb;
 maximum jsonb:='[]';patch jsonb;item jsonb;tier text;fga_user text;object_name text;fga_row jsonb;tuples jsonb:='[]';
 ordinal integer:=0;i integer:=0;cost integer;created timestamptz:=transaction_timestamp();scope_value integer;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind'<>'binding' OR proof->>'purpose'<>'decision' OR p_mode NOT IN ('authorize','create','metadata')
 OR jsonb_typeof(p_input) IS DISTINCT FROM 'object' OR coalesce(p_input->>'id','')='' THEN
  RAISE EXCEPTION 'binding sequence input lacks participant identity' USING ERRCODE='42501';END IF;
 IF p_mode='authorize' THEN
  IF p_input-ARRAY['id']<>'{}' THEN RAISE EXCEPTION 'authorization cannot carry mutation fields' USING ERRCODE='42501';END IF;
 ELSIF p_mode='metadata' THEN
  IF p_input-ARRAY['id','deletion_protection','labels']<>'{}' OR
   (p_input ? 'deletion_protection' AND jsonb_typeof(p_input->'deletion_protection') IS DISTINCT FROM 'boolean') OR
   (p_input ? 'labels' AND jsonb_typeof(p_input->'labels') IS DISTINCT FROM 'object') THEN
   RAISE EXCEPTION 'binding metadata mask is not closed' USING ERRCODE='42501';END IF;
  SELECT to_jsonb(b) INTO STRICT parent FROM kaname.access_bindings b WHERE b.id=p_input->>'id' FOR UPDATE;
  FOREACH tier IN ARRAY ARRAY['deletion_protection','labels'] LOOP
   IF NOT p_input ? tier THEN CONTINUE;END IF;
   next_parent:=parent||jsonb_build_object(tier,p_input->tier);
   IF next_parent<>parent THEN
    ordinal:=ordinal+1;maximum:=maximum||jsonb_build_array(kaname._authority_binding_journal_v3('access_bindings','UPDATE',parent,next_parent,next_parent,ordinal));
   END IF;
   parent:=next_parent;
  END LOOP;
 ELSE
  IF p_input-ARRAY['id','subject_type','subject_id','role_id','resource_type','resource_id','status','expires_at',
   'granted_by_user_id','revoked_at','revoked_by_user_id','scope','deletion_protection','labels','target','target_digest',
   'granted_relation','is_system','delegation_id','subjects']<>'{}' THEN
   RAISE EXCEPTION 'binding create fields are not closed' USING ERRCODE='42501';END IF;
  subjects:=p_input->'subjects';
  IF jsonb_typeof(subjects) IS DISTINCT FROM 'array' OR jsonb_array_length(subjects) NOT BETWEEN 1 AND 32 THEN
   RAISE EXCEPTION 'binding subjects exceed closed cap' USING ERRCODE='54000';END IF;
  scope_value:=(p_input->>'scope')::integer;
  IF scope_value=0 THEN scope_value:=CASE p_input->>'resource_type' WHEN 'cluster' THEN 1 WHEN 'account' THEN 2 WHEN 'cloud' THEN 2 ELSE 3 END;END IF;
  parent:=to_jsonb(jsonb_populate_record(NULL::kaname.access_bindings,(p_input-'subjects')||jsonb_build_object(
   'scope',scope_value,'created_at',created,'status',coalesce(nullif(p_input->>'status',''),'ACTIVE'),
   'role_id',nullif(p_input->>'role_id',''),'delegation_id',nullif(p_input->>'delegation_id',''),
   'revocation_reason',NULL,'grant_capability_version',0)));
  SELECT to_jsonb(r) INTO STRICT role_row FROM kaname.roles r WHERE r.id=parent->>'role_id' FOR SHARE;
  ordinal:=ordinal+1;maximum:=maximum||jsonb_build_array(kaname._authority_binding_journal_v3('access_bindings','INSERT',NULL,parent,parent,ordinal));
  next_parent:=parent||jsonb_build_object('grant_capability_version',1);
  ordinal:=ordinal+1;maximum:=maximum||jsonb_build_array(kaname._authority_binding_journal_v3('access_bindings','UPDATE',parent,next_parent,next_parent,ordinal));
  parent:=next_parent;
  tier:=kaname._authority_binding_scope_tier_v3(parent->>'resource_type',role_row->'rules',role_row->'permissions');
  FOR item IN SELECT value FROM jsonb_array_elements(subjects) LOOP
   IF item-ARRAY['type','id']<>'{}' OR coalesce(item->>'id','')='' OR
    item->>'type' NOT IN ('user','service_account','group','system_class') THEN
    RAISE EXCEPTION 'binding subject is not normalized' USING ERRCODE='42501';END IF;
   source_row:=jsonb_build_object('binding_id',parent->>'id','subject_type',item->>'type','subject_id',item->>'id',
    'ordinal',i,'resource_type',parent->>'resource_type','resource_id',parent->>'resource_id');i:=i+1;
   ordinal:=ordinal+1;maximum:=maximum||jsonb_build_array(kaname._authority_binding_journal_v3('access_binding_subjects','INSERT',NULL,source_row,parent,ordinal));
   IF tier IS NOT NULL THEN
    fga_user:=(item->>'type')||':'||(item->>'id')||CASE WHEN item->>'type'='group' THEN '#member' ELSE '' END;
    tuples:=tuples||jsonb_build_array(jsonb_build_object('user',fga_user,'relation',tier,
     'object',(parent->>'resource_type')||':'||(parent->>'resource_id')));
   END IF;
  END LOOP;
  tuples:=tuples||jsonb_build_array(jsonb_build_object('user',(parent->>'resource_type')||':'||(parent->>'resource_id'),
   'relation',parent->>'resource_type','object','iam_access_binding:'||(parent->>'id')));
  FOR item IN SELECT jsonb_build_object('user',value->>'user','object',value->>'object','relation',min(value->>'relation'))
   FROM jsonb_array_elements(tuples) GROUP BY value->>'object',value->>'user' ORDER BY value->>'object',value->>'user' LOOP
   ordinal:=ordinal+1;fga_row:=jsonb_build_object('event_type','fga.tuple.write','payload',item);
   maximum:=maximum||jsonb_build_array(jsonb_build_object('table','fga_outbox','origin',
    jsonb_build_object('family','binding.create','binding',parent->>'id','ordinal',ordinal),
    'ordinal',ordinal,'row',fga_row,'stamp','transaction'));
  END LOOP;
 END IF;
 cost:=kaname._authority_sequence_reserve_v3('binding',maximum,256);
 PERFORM kaname._authority_sequence_freeze_v3(jsonb_build_object('kind','binding.decision','mode',p_mode,'id',p_input->>'id','created_at',created));
END $$;

CREATE FUNCTION kaname.authority_binding_sequence_finalize_v3() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;proof jsonb;ordinals integer[];
BEGIN
 program:=kaname._authority_sequence_store_v3();proof:=kaname.authority_protocol_attestation();
 IF program IS NULL OR proof IS NULL OR program->>'family'<>'binding' OR program#>>'{frozen,kind}'<>'binding.decision'
 OR (proof->>'decision_at')::timestamptz<=(program->>'staged_decision_at')::timestamptz THEN
  RAISE EXCEPTION 'binding decision did not refresh after all reservations' USING ERRCODE='42501';END IF;
 SELECT coalesce(array_agg((value->>'ordinal')::integer ORDER BY (value->>'ordinal')::integer),ARRAY[]::integer[]) INTO ordinals
 FROM jsonb_array_elements(program->'maximum');
 PERFORM kaname._authority_sequence_select_v3(ordinals,(proof->>'decision_at')::timestamptz);
END $$;

CREATE FUNCTION kaname.authority_binding_insert_stamp_v3(p_id text) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;
BEGIN
 program:=kaname._authority_sequence_store_v3();
 IF program IS NULL THEN RETURN NULL;END IF;
 IF program->>'family'<>'binding' OR program#>>'{frozen,mode}'<>'create'
 OR program#>>'{frozen,id}' IS DISTINCT FROM p_id OR jsonb_typeof(program->'selected') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'binding insert does not belong to selected create' USING ERRCODE='42501';END IF;
 RETURN (program#>>'{frozen,created_at}')::timestamptz;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- RR compiler замыкает один полный binding. Owner хранит проверенный
-- maximum; caller получает только счётчики, не разрешение и не reserved IDs.
CREATE FUNCTION kaname.authority_binding_stage_sequence_capture_v3(p_input jsonb,p_accounts text[],p_epochs jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE invoker oid;owner_oid oid;source_index jsonb;entry record;actual record;bundle record;
 binding jsonb;selectors jsonb;members jsonb;ledger jsonb;subjects integer;types text[]:=ARRAY[]::text[];
 catalog jsonb;coordinate jsonb;typ text;identifier text;graph jsonb;ancestry jsonb;certificate jsonb;
 current_members jsonb;current_ledger jsonb;member_proof jsonb;ledger_proof jsonb;
 supplied jsonb:='{}'::jsonb;commands jsonb:='[]'::jsonb;maximum jsonb:='[]'::jsonb;
 command jsonb;tuple_value jsonb;seen_tuples jsonb;key text;supplied_count integer;
 narrow boolean;global_scope boolean;accounts text[];scope_result record;grantee record;
 used_rows integer:=0;used_reads integer:=0;
BEGIN
 IF current_setting('transaction_isolation')<>'repeatable read' OR p_rows IS NULL OR p_rows<0 OR p_rows>100000
 OR p_reads IS NULL OR p_reads<0 OR p_reads>4096 OR jsonb_typeof(p_input) IS DISTINCT FROM 'object'
 OR p_input-ARRAY['binding','converge','sources','coordinates']<>'{}'::jsonb
 OR jsonb_typeof(p_input->'converge') IS DISTINCT FROM 'boolean'
 OR jsonb_typeof(p_input->'coordinates') IS DISTINCT FROM 'array'
 OR jsonb_array_length(p_input->'coordinates')>100000 OR octet_length(p_input::text)>67108864 THEN
  RAISE EXCEPTION 'invalid full binding RR compiler input' USING ERRCODE='42501';END IF;
 SELECT oid INTO STRICT invoker FROM pg_catalog.pg_roles WHERE rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
 SELECT oid INTO STRICT owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
 IF NOT has_database_privilege(invoker,current_database(),'TEMP') OR NOT has_table_privilege(invoker,'kaname.authority_semantic_identity','SELECT') THEN
  RAISE EXCEPTION 'binding stage requires original temporary/read privileges' USING ERRCODE='42501';END IF;
 IF to_regclass('pg_temp.kaname_binding_sequence_snapshot') IS NOT NULL THEN
  RAISE EXCEPTION 'binding owner snapshot already exists' USING ERRCODE='42501';END IF;
 source_index:=kaname._authority_resource_capture_index_v2(p_input->'sources',p_rows);
 FOR entry IN SELECT source_entry.* FROM jsonb_each(source_index) source_entry ORDER BY source_entry.key COLLATE "C" LOOP
  used_reads:=used_reads+1;IF used_reads>p_reads THEN RAISE EXCEPTION 'binding source reads exceeded' USING ERRCODE='54000';END IF;
  SELECT * INTO STRICT actual FROM kaname._authority_binding_stage_source_v3(entry.value->'source',invoker,p_rows-used_rows);
  used_rows:=used_rows+actual.logical_rows;
  IF actual.states IS DISTINCT FROM (SELECT coalesce(jsonb_agg(value ORDER BY value::text COLLATE "C"),'[]'::jsonb) FROM jsonb_array_elements(entry.value->'states')) THEN
   RAISE EXCEPTION 'binding RR source witness differs from canonical rows' USING ERRCODE='42501';END IF;
 END LOOP;
 binding:=kaname._authority_resource_require_capture_v2(source_index,8,'binding',p_input->>'binding');
 IF jsonb_array_length(binding->'states')<>1 THEN RAISE EXCEPTION 'binding RR root absent' USING ERRCODE='42501';END IF;
 binding:=binding->'states'->0->2;
 IF binding->>'status'<>'ACTIVE' THEN RAISE EXCEPTION 'binding RR root inactive' USING ERRCODE='42501';END IF;
 members:=kaname._authority_resource_require_capture_v2(source_index,10,'binding',binding->>'id');
 ledger:=kaname._authority_resource_require_capture_v2(source_index,11,'binding',binding->>'id');
 subjects:=greatest(1,jsonb_array_length(kaname._authority_resource_require_capture_v2(source_index,9,'binding',binding->>'id')->'states'));
 selectors:='[]'::jsonb;
 IF nullif(binding->>'role_id','') IS NOT NULL THEN
  SELECT coalesce(jsonb_agg(value->2),'[]'::jsonb) INTO selectors FROM jsonb_array_elements(kaname._authority_resource_require_capture_v2(source_index,13,'role',binding->>'role_id')->'states');
 END IF;
 SELECT coalesce(array_agg(DISTINCT value),'{}'::text[]) INTO types FROM (
  SELECT jsonb_array_elements_text(coalesce(nullif(s->'object_types','null'::jsonb),'[]'::jsonb)) value FROM jsonb_array_elements(selectors) s
  UNION SELECT value->2->>'object_type' FROM jsonb_array_elements(members->'states')
  UNION SELECT 'iam.'||(binding->>'resource_type') WHERE jsonb_array_length(selectors)>0) q;
 narrow:=binding->>'resource_type'='account' AND jsonb_array_length(coalesce(nullif(binding#>'{target,resources}','null'::jsonb),'[]'::jsonb))=0
  AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(selectors) s WHERE s->>'arm'<>'anchor' OR s->>'container_type' IS NOT NULL);
 global_scope:=NOT narrow;accounts:=CASE WHEN narrow THEN ARRAY[binding->>'resource_id'] ELSE NULL END;
 SELECT * INTO STRICT actual FROM kaname._authority_binding_stage_coordinates_v3(binding,types,narrow,invoker,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+actual.logical_rows;used_reads:=used_reads+actual.logical_reads;
 FOR coordinate IN SELECT value FROM jsonb_array_elements(p_input->'coordinates') LOOP
  IF coordinate-ARRAY['type','id','desired','commands']<>'{}'::jsonb THEN RAISE EXCEPTION 'duplicate or invalid binding coordinate' USING ERRCODE='42501';END IF;
 END LOOP;
 -- Карта полного census строится один раз; совпадающие ключи не скрываются агрегатом.
 SELECT coalesce(jsonb_object_agg(c.coordinate_key,true),'{}'::jsonb),count(DISTINCT c.coordinate_key COLLATE "C")
 INTO supplied,supplied_count FROM (
  SELECT jsonb_build_array(q.value->>'type',q.value->>'id')::text AS coordinate_key
  FROM jsonb_array_elements(p_input->'coordinates') q(value)) c;
 IF supplied_count<>jsonb_array_length(p_input->'coordinates') THEN
  RAISE EXCEPTION 'duplicate or invalid binding coordinate' USING ERRCODE='42501';END IF;
 IF supplied IS DISTINCT FROM actual.coordinates THEN RAISE EXCEPTION 'binding coordinate census incomplete' USING ERRCODE='42501';END IF;
 used_reads:=used_reads+1;used_rows:=used_rows+1;
 IF used_reads>p_reads OR used_rows>p_rows THEN RAISE EXCEPTION 'binding bundle budget exceeded' USING ERRCODE='54000';END IF;
 SELECT b.* INTO STRICT bundle FROM kaname.authority_bundle_handoff b WHERE singleton;
 IF encode(sha256(bundle.catalog_json),'hex') IS DISTINCT FROM bundle.catalog_id
 OR encode(sha256(convert_to(bundle.model_source,'UTF8')),'hex') IS DISTINCT FROM bundle.model_id THEN
  RAISE EXCEPTION 'binding canonical bundle corrupt' USING ERRCODE='42501';END IF;
 catalog:=convert_from(bundle.catalog_json,'UTF8')::jsonb;
 -- Тот же coordinate order, что keyset typ/id; map iteration caller его не выбирает.
 FOR coordinate IN SELECT value FROM jsonb_array_elements(p_input->'coordinates') ORDER BY value->>'type' COLLATE "C",value->>'id' COLLATE "C" LOOP
  typ:=coordinate->>'type';identifier:=coordinate->>'id';
  graph:=kaname._authority_resource_projection_v2(source_index,typ,identifier);
  ancestry:=kaname._authority_resource_ancestor_graph_v2(source_index,catalog,graph);
  graph:=graph||jsonb_build_object('ancestors',ancestry->'ancestors');
  certificate:=kaname._authority_resource_coordinate_certificate_v2(source_index,catalog,binding->>'id',graph,coordinate->'desired');
  SELECT coalesce(jsonb_agg(value->2),'[]'::jsonb) INTO current_members FROM jsonb_array_elements(members->'states') WHERE value->2->>'object_type'=typ AND value->2->>'object_id'=identifier;
  SELECT coalesce(jsonb_agg(value->2),'[]'::jsonb) INTO current_ledger FROM jsonb_array_elements(ledger->'states') WHERE value->2->>'member_object_type'=typ AND value->2->>'member_object_id'=identifier;
  member_proof:=kaname._authority_resource_member_obligations_v2(binding,current_members,certificate->'desired',coordinate->'commands',false,true);
  -- Converge явно включает completion даже при одном subject; остальные
  -- ветви ledger verifier используют фактический subject_count без подмены.
  ledger_proof:=kaname._authority_resource_ledger_obligations_v2(binding,current_ledger,member_proof,coordinate->'commands',false,true,
   CASE WHEN (p_input->>'converge')::boolean THEN greatest(2,subjects) ELSE subjects END);
  used_rows:=used_rows+(certificate->>'work')::integer+jsonb_array_length(coordinate->'commands');
  IF used_rows>p_rows THEN RAISE EXCEPTION 'binding certificate work exceeded' USING ERRCODE='54000';END IF;
  IF NOT global_scope AND typ='iam.group' THEN
   used_reads:=used_reads+1;IF used_reads>p_reads THEN RAISE EXCEPTION 'binding scope read budget exceeded' USING ERRCODE='54000';END IF;
   SELECT * INTO STRICT scope_result FROM kaname.authority_group_object_scopes(identifier);
   global_scope:=scope_result.global_scope;accounts:=accounts||scope_result.accounts;
  END IF;
  seen_tuples:='{}'::jsonb;
  FOR command IN SELECT value FROM jsonb_array_elements(coordinate->'commands') LOOP
   IF command->>'Kind' NOT IN ('write','delete') THEN CONTINUE;END IF;
   FOR tuple_value IN SELECT value FROM jsonb_array_elements(command->'Tuples') LOOP
    key:=jsonb_build_array(command->>'Kind',tuple_value)::text;
    IF seen_tuples ? key THEN RAISE EXCEPTION 'binding duplicate physical tuple within coordinate' USING ERRCODE='42501';END IF;
    seen_tuples:=seen_tuples||jsonb_build_object(key,true);
    IF tuple_value->>'Object' NOT LIKE 'iam_group:%' THEN global_scope:=true;END IF;
   END LOOP;
  END LOOP;
 END LOOP;
 SELECT coalesce(array_agg(DISTINCT x COLLATE "C" ORDER BY x COLLATE "C"),ARRAY[]::text[]) INTO accounts FROM unnest(accounts) x;
 IF cardinality(accounts)>256 THEN global_scope:=true;END IF;
 IF global_scope THEN accounts:=NULL;END IF;
 IF accounts IS DISTINCT FROM p_accounts OR kaname.authority_binding_epoch_read(accounts) IS DISTINCT FROM p_epochs THEN
  RAISE EXCEPTION 'binding owner scope/epochs differ' USING ERRCODE='P1034';END IF;
 -- Проекция разрешена только после всех исходных coordinate/member/ledger proofs.
 -- Номер команды включает ВСЕ виды команд, в том числе не создающие FGA событие.
 WITH ordered_coordinates AS (
  SELECT q.value,row_number() OVER(ORDER BY q.value->>'type' COLLATE "C",q.value->>'id' COLLATE "C")::integer AS coordinate_no
  FROM jsonb_array_elements(p_input->'coordinates') q(value)
 ), numbered_commands AS (
  SELECT c.coordinate_no,t.value AS body,
   row_number() OVER(ORDER BY c.coordinate_no,t.position)::integer AS command_no
  FROM ordered_coordinates c CROSS JOIN LATERAL jsonb_array_elements(c.value->'commands') WITH ORDINALITY t(value,position)
 )
 SELECT coalesce(jsonb_agg(jsonb_build_object('coordinate',c.coordinate_no,'command',c.command_no,'body',c.body)
  ORDER BY c.command_no),'[]'::jsonb) INTO commands FROM numbered_commands c;
 -- Phase 1 удалений действительно идёт после всех новых ledger claims.
 -- Группы и итоговый максимум агрегируются один раз, без копирования растущего массива.
 WITH command_groups AS (
  SELECT c.value->'coordinate' AS coordinate_no,c.value->'command' AS command_no,
   c.value->'body'->>'Kind' AS command_kind,g.object_name,g.user_name,g.relations
  FROM jsonb_array_elements(commands) c(value)
  CROSS JOIN LATERAL (
   SELECT t.value->>'Object' AS object_name,t.value->>'User' AS user_name,
    jsonb_agg(DISTINCT (t.value->>'Relation') COLLATE "C" ORDER BY (t.value->>'Relation') COLLATE "C") AS relations
   FROM jsonb_array_elements(CASE WHEN c.value->'body'->>'Kind' NOT IN ('write','delete') THEN '[]'::jsonb
    ELSE c.value->'body'->'Tuples' END) t(value)
   GROUP BY t.value->>'Object',t.value->>'User'
  ) g
  WHERE (c.value->'body'->>'Kind' NOT IN ('write','delete')) IS NOT TRUE
 ), numbered_groups AS (
  SELECT g.*,row_number() OVER(ORDER BY CASE WHEN g.command_kind='delete' THEN 1 ELSE 0 END,
   (g.command_no::text)::integer,g.object_name COLLATE "C",g.user_name COLLATE "C")::integer AS effect_no
  FROM command_groups g
 ), descriptors AS (
  SELECT g.effect_no,jsonb_build_object('table','fga_outbox','ordinal',g.effect_no,
   'origin',jsonb_build_object('family','binding.stage','binding',binding->>'id','coordinate',g.coordinate_no,
    'command',g.command_no,'object',g.object_name,'user',g.user_name),
   'row',jsonb_build_object('event_type','fga.tuple.'||g.command_kind,
    'payload',jsonb_build_object('object',g.object_name,'user',g.user_name)||
     CASE WHEN jsonb_array_length(g.relations)=1 THEN jsonb_build_object('relation',g.relations->>0)
      ELSE jsonb_build_object('relations',g.relations)||
       CASE WHEN g.command_kind='write' THEN jsonb_build_object('relation',g.relations->>0) ELSE '{}'::jsonb END END),
   'stamp',CASE WHEN g.command_kind='delete' THEN 'decision' ELSE 'transaction' END) AS descriptor
  FROM numbered_groups g
 )
 SELECT coalesce(jsonb_agg(d.descriptor ORDER BY d.effect_no),'[]'::jsonb) INTO maximum FROM descriptors d;
 IF jsonb_array_length(maximum)>100000 OR octet_length(maximum::text)>67108864 THEN RAISE EXCEPTION 'binding maximum exceeded' USING ERRCODE='54000';END IF;
 CREATE TEMP TABLE kaname_binding_sequence_snapshot(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),backend integer NOT NULL,
  invoker_oid oid NOT NULL,stage_xid text NOT NULL,binding_id text NOT NULL,model_id text NOT NULL,catalog_id text NOT NULL,projector_version text NOT NULL,
  accounts text[],epochs jsonb NOT NULL,expires_at timestamptz,commands jsonb NOT NULL,maximum jsonb NOT NULL,consumed boolean NOT NULL DEFAULT false) ON COMMIT PRESERVE ROWS;
 REVOKE ALL ON pg_temp.kaname_binding_sequence_snapshot FROM PUBLIC;
 FOR grantee IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE c.oid='pg_temp.kaname_binding_sequence_snapshot'::regclass AND a.grantee<>owner_oid LOOP
  EXECUTE format('REVOKE ALL ON pg_temp.kaname_binding_sequence_snapshot FROM %I',grantee.rolname);
 END LOOP;
 INSERT INTO pg_temp.kaname_binding_sequence_snapshot(backend,invoker_oid,stage_xid,binding_id,model_id,catalog_id,projector_version,accounts,epochs,expires_at,commands,maximum)
 VALUES(pg_backend_pid(),invoker,pg_current_xact_id()::text,binding->>'id',bundle.model_id,bundle.catalog_id,bundle.projector_version,accounts,p_epochs,(binding->>'expires_at')::timestamptz,commands,maximum);
 RETURN QUERY SELECT used_rows,used_reads;
END $$;

-- Не выдаёт snapshot/IDs runtime. Связь backend + invoker + новый xid и
-- immutable bundle проверяется до выдачи sequence reservation.
CREATE FUNCTION kaname._authority_binding_stage_snapshot_v3() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE storage oid;owner_oid oid;proof jsonb;result jsonb;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind'<>'binding' OR proof->>'purpose'<>'participant' THEN
  RAISE EXCEPTION 'binding stage participant required' USING ERRCODE='42501';END IF;
 storage:=to_regclass('pg_temp.kaname_binding_sequence_snapshot');
 SELECT oid INTO STRICT owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
 IF storage IS NULL OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=storage AND c.relowner=owner_oid AND c.relpersistence='t' AND c.relkind='r')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE c.oid=storage AND a.grantee<>owner_oid) THEN
  RAISE EXCEPTION 'untrusted binding owner snapshot' USING ERRCODE='42501';END IF;
 SELECT to_jsonb(s) INTO STRICT result FROM pg_temp.kaname_binding_sequence_snapshot s WHERE singleton;
 IF result->>'backend' IS DISTINCT FROM proof->>'backend' OR result->>'invoker_oid' IS DISTINCT FROM proof->>'invoker_oid'
 OR result->>'stage_xid'=proof->>'transaction_id' OR result->>'model_id' IS DISTINCT FROM proof->>'model_id'
 OR result->>'catalog_id' IS DISTINCT FROM proof->>'catalog_id' OR result->>'projector_version' IS DISTINCT FROM proof->>'projector_version' THEN
  RAISE EXCEPTION 'binding owner snapshot identity/lifetime changed' USING ERRCODE='P1034';END IF;
 RETURN result;
END $$;

CREATE FUNCTION kaname.authority_binding_stage_sequence_prepare_v3(p_binding text,p_accounts text[],p_epochs jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE snapshot jsonb;proof jsonb;expected jsonb;actual jsonb;used integer;count_rows integer;
BEGIN
 snapshot:=kaname._authority_binding_stage_snapshot_v3();proof:=kaname.authority_protocol_attestation();
 IF current_setting('transaction_isolation')<>'read committed' OR snapshot->>'binding_id' IS DISTINCT FROM p_binding
 OR snapshot->>'consumed' IS DISTINCT FROM 'false' OR snapshot->'epochs' IS DISTINCT FROM p_epochs
 OR snapshot->'accounts' IS DISTINCT FROM coalesce(to_jsonb(p_accounts),'null'::jsonb)
 OR p_rows IS NULL OR p_rows<0 OR p_rows>100000 OR p_reads IS NULL OR p_reads<2 OR p_reads>4096 THEN
  RAISE EXCEPTION 'binding stage reservation request differs from owner snapshot' USING ERRCODE='42501';END IF;
 IF (p_accounts IS NULL AND proof->>'mode'<>'global')
 OR (p_accounts IS NOT NULL AND proof->>'mode'='accounts' AND NOT proof->'accounts' @> to_jsonb(p_accounts)) THEN
  RAISE EXCEPTION 'binding staged footprint exceeds signed scope' USING ERRCODE='42501';END IF;
 -- Runner уже получил exact epoch locks до любых mutable row locks. Этот
 -- повтор читает только held generations; не расширяет inventory/source graph.
 IF kaname.authority_binding_epoch_read(p_accounts) IS DISTINCT FROM p_epochs THEN
  RAISE EXCEPTION 'binding owner captured source changed' USING ERRCODE='P1034';END IF;
 SELECT coalesce(jsonb_agg(value->'body' ORDER BY (value->>'command')::integer),'[]'::jsonb)
 INTO expected FROM jsonb_array_elements(snapshot->'commands');
 count_rows:=jsonb_array_length(expected)+jsonb_array_length(snapshot->'maximum');
 IF count_rows>p_rows THEN RAISE EXCEPTION 'binding stage reservation rows exceeded' USING ERRCODE='54000';END IF;
 SELECT coalesce(jsonb_agg(q.body ORDER BY q.seq),'[]'::jsonb) INTO actual FROM
  (SELECT seq,body FROM pg_temp.kaname_binding_stage ORDER BY seq LIMIT p_rows+1) q;
 IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION 'binding runtime spool differs from owner program' USING ERRCODE='42501';END IF;
 used:=kaname._authority_sequence_reserve_v3('binding',snapshot->'maximum',p_reads-2);
 PERFORM kaname._authority_sequence_freeze_v3(jsonb_build_object('kind','binding.stage','binding',p_binding,
  'expires_at',snapshot->'expires_at','epochs',p_epochs,'accounts',snapshot->'accounts'));
 UPDATE pg_temp.kaname_binding_sequence_snapshot SET consumed=true WHERE singleton;
 RETURN QUERY SELECT count_rows,used+2;
END $$;

CREATE FUNCTION kaname.authority_binding_stage_sequence_finalize_v3(p_binding text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;proof jsonb;ordinals integer[];at_time timestamptz;
BEGIN
 program:=kaname._authority_sequence_store_v3();proof:=kaname.authority_protocol_attestation();
 IF program IS NULL OR program#>>'{frozen,kind}'<>'binding.stage' OR program#>>'{frozen,binding}' IS DISTINCT FROM p_binding
 OR program->'selected' IS DISTINCT FROM 'null'::jsonb THEN
  RAISE EXCEPTION 'binding stage frozen maximum absent/already selected' USING ERRCODE='42501';END IF;
 at_time:=(proof->>'decision_at')::timestamptz;
 IF at_time IS NULL OR at_time<=(program->>'staged_decision_at')::timestamptz THEN RAISE EXCEPTION 'binding stage final clock was not refreshed' USING ERRCODE='42501';END IF;
 -- Единственное ветвление после часов — чистый TTL subset; новых source reads,
 -- locks, ID allocation и расширения программы здесь нет.
 ordinals:=ARRAY[]::integer[];
 IF program#>>'{frozen,expires_at}' IS NULL OR (program#>>'{frozen,expires_at}')::timestamptz>at_time THEN
  SELECT coalesce(array_agg((value->>'ordinal')::integer ORDER BY (value->>'ordinal')::integer),ARRAY[]::integer[]) INTO ordinals FROM jsonb_array_elements(program->'maximum');
 END IF;
 PERFORM kaname._authority_sequence_select_v3(ordinals,at_time);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Замкнутый RR witness reader. SQL/имена таблиц не приходят от caller.
-- Helper не выдаёт authority и не берёт business locks: он подтверждает
-- исходные bytes внутри того же RR snapshot до закрытого owner stage.
CREATE FUNCTION kaname._authority_binding_stage_source_v3(p_source jsonb,p_invoker oid,p_rows integer)
RETURNS TABLE(states jsonb,logical_rows integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE kind integer;typ text;identifier text;table_name text;predicate text;
 statement text;item record;result jsonb:='[]'::jsonb;used integer:=0;
BEGIN
 IF current_setting('transaction_isolation')<>'repeatable read' OR p_rows<0 OR p_rows>100000
 OR jsonb_typeof(p_source) IS DISTINCT FROM 'object' OR coalesce(p_source->>'projection','')<>'' THEN
  RAISE EXCEPTION 'invalid binding RR source witness' USING ERRCODE='42501';END IF;
 kind:=(p_source->>'kind')::integer;typ:=p_source->>'type';identifier:=p_source->>'id';
 IF coalesce(identifier,'')='' OR coalesce(typ,'')='' THEN RAISE EXCEPTION 'missing binding RR source identity' USING ERRCODE='42501';END IF;
 CASE kind
 WHEN 1 THEN table_name:='projects';predicate:='r.id=$2';IF typ<>'project' THEN RAISE EXCEPTION 'source type' USING ERRCODE='42501';END IF;
 WHEN 2 THEN table_name:='resource_mirror';predicate:='r.object_type=$1 AND r.object_id=$2';
 WHEN 3 THEN table_name:='resource_parent_edge';predicate:='r.object_type=$1 AND r.object_id=$2';
 WHEN 8 THEN table_name:='access_bindings';predicate:='r.id=$2';
 WHEN 9 THEN table_name:='access_binding_subjects';predicate:='r.binding_id=$2';
 WHEN 10 THEN table_name:='access_binding_target_members';predicate:='r.binding_id=$2';
 WHEN 11 THEN table_name:='access_binding_emitted_tuples';predicate:='r.binding_id=$2';
 WHEN 12 THEN table_name:='roles';predicate:='r.id=$2';
 WHEN 13 THEN table_name:='role_rule_selectors';predicate:='r.role_id=$2';
 WHEN 21 THEN table_name:='access_binding_target_members';predicate:='r.object_type=$1 AND r.object_id=$2';
 WHEN 22 THEN table_name:='access_binding_emitted_tuples';predicate:='r.member_object_type=$1 AND r.member_object_id=$2';
 WHEN 23 THEN table_name:='accounts';predicate:='r.id=$2';IF typ<>'account' THEN RAISE EXCEPTION 'source type' USING ERRCODE='42501';END IF;
 WHEN 30 THEN
  table_name:=CASE typ WHEN 'iam.account' THEN 'accounts' WHEN 'iam.project' THEN 'projects'
   WHEN 'iam.role' THEN 'roles' WHEN 'iam.group' THEN 'groups' WHEN 'iam.serviceAccount' THEN 'service_accounts'
   WHEN 'iam.accessBinding' THEN 'access_bindings' WHEN 'iam.user' THEN 'users' END;
  predicate:='r.id=$2';
 WHEN 31 THEN table_name:='memberships';predicate:='r.user_id=$2';IF typ<>'iam.user' THEN RAISE EXCEPTION 'source type' USING ERRCODE='42501';END IF;
 ELSE RAISE EXCEPTION 'binding RR source kind outside closed graph' USING ERRCODE='42501';
 END CASE;
 IF (kind BETWEEN 8 AND 11 AND typ<>'binding') OR (kind IN (12,13) AND typ<>'role') OR table_name IS NULL
 OR NOT has_table_privilege(p_invoker,to_regclass('kaname.'||table_name),'SELECT') THEN
  RAISE EXCEPTION 'binding RR source requires original SELECT' USING ERRCODE='42501';END IF;
 statement:=format('SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r)) v FROM kaname.%I r WHERE %s LIMIT $3',table_name,predicate);
 FOR item IN EXECUTE statement USING typ,identifier,p_rows+1 LOOP
  used:=used+1;IF used>p_rows THEN RAISE EXCEPTION 'binding RR source budget exceeded' USING ERRCODE='54000';END IF;
  result:=result||jsonb_build_array(item.v);
 END LOOP;
 SELECT coalesce(jsonb_agg(value ORDER BY value::text COLLATE "C"),'[]'::jsonb) INTO result FROM jsonb_array_elements(result);
 RETURN QUERY SELECT result,used;
END $$;

-- Точный candidate predicate bindingCoordinatePage, включая membership
-- accounts для iam.user и прежние members исчезнувших объектов.
CREATE FUNCTION kaname._authority_binding_stage_coordinates_v3(p_binding jsonb,p_types text[],p_narrow boolean,p_invoker oid,p_rows integer,p_reads integer)
RETURNS TABLE(coordinates jsonb,logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE typ text;table_name text;join_sql text;account_sql text;source text;statement text;scope text;
 item record;result jsonb:='{}'::jsonb;used integer:=0;reads integer:=0;
BEGIN
 IF current_setting('transaction_isolation')<>'repeatable read' OR p_rows<0 OR p_rows>100000 OR p_reads<0 OR p_reads>4096
 OR cardinality(p_types)>4096 OR p_binding->>'id' IS NULL OR p_narrow IS NULL THEN
  RAISE EXCEPTION 'invalid binding candidate census' USING ERRCODE='42501';END IF;
 IF p_narrow THEN scope:=p_binding->>'resource_id';END IF;
 FOR typ IN SELECT DISTINCT x COLLATE "C" FROM unnest(p_types) x ORDER BY 1 LOOP
  reads:=reads+1;IF reads>p_reads THEN RAISE EXCEPTION 'binding census read budget exceeded' USING ERRCODE='54000';END IF;
  join_sql:='';table_name:=NULL;
  CASE typ
  WHEN 'iam.account' THEN table_name:='accounts';account_sql:='o.id=$2';
  WHEN 'iam.project' THEN table_name:='projects';account_sql:='o.account_id=$2';
  WHEN 'iam.role' THEN table_name:='roles';join_sql:='LEFT JOIN kaname.projects p ON p.id=o.project_id';account_sql:='coalesce(o.account_id,p.account_id,'''')=$2';
  WHEN 'iam.group' THEN table_name:='groups';account_sql:='o.account_id=$2';
  WHEN 'iam.serviceAccount' THEN table_name:='service_accounts';account_sql:='o.account_id=$2';
  WHEN 'iam.user' THEN table_name:='users';account_sql:='EXISTS(SELECT 1 FROM kaname.memberships m WHERE m.user_id=o.id AND m.account_id=$2)';
  WHEN 'iam.accessBinding' THEN table_name:='access_bindings';join_sql:='LEFT JOIN kaname.projects p ON o.resource_type=''project'' AND p.id=o.resource_id';account_sql:='CASE WHEN o.resource_type=''account'' THEN o.resource_id ELSE coalesce(p.account_id,'''') END=$2';
  ELSE NULL;
  END CASE;
  IF NOT has_table_privilege(p_invoker,'kaname.access_binding_target_members','SELECT')
  OR NOT has_table_privilege(p_invoker,'kaname.projects','SELECT')
  OR (typ='iam.user' AND NOT has_table_privilege(p_invoker,'kaname.memberships','SELECT')) THEN
   RAISE EXCEPTION 'binding candidate source SELECT absent' USING ERRCODE='42501';END IF;
  IF table_name IS NULL THEN
   table_name:='resource_mirror';
   source:='SELECT m.object_id id FROM kaname.resource_mirror m LEFT JOIN kaname.projects p ON p.id=m.parent_project_id WHERE m.object_type=$1 AND ($2::text IS NULL OR coalesce(nullif(m.parent_account_id,''''),p.account_id,'''')=$2)';
  ELSE source:=format('SELECT o.id FROM kaname.%I o %s WHERE ($2::text IS NULL OR %s)',table_name,join_sql,account_sql);END IF;
  IF NOT has_table_privilege(p_invoker,to_regclass('kaname.'||table_name),'SELECT') THEN RAISE EXCEPTION 'binding candidate SELECT absent' USING ERRCODE='42501';END IF;
  statement:='SELECT id FROM ('||source||' UNION SELECT object_id FROM kaname.access_binding_target_members WHERE binding_id=$3 AND object_type=$1) q LIMIT $4';
  FOR item IN EXECUTE statement USING typ,scope,p_binding->>'id',p_rows-used+1 LOOP
   used:=used+1;IF used>p_rows THEN RAISE EXCEPTION 'binding candidate rows exceeded' USING ERRCODE='54000';END IF;
   result:=result||jsonb_build_object(jsonb_build_array(typ,item.id)::text,true);
  END LOOP;
 END LOOP;
 RETURN QUERY SELECT result,used,reads;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Withdrawal compiler выбирает carrier сам: один binding либо полный
-- актуальный delegation predicate. Runtime spool не задаёт journal/FGA программу.
CREATE FUNCTION kaname.authority_binding_withdrawal_sequence_prepare_v3(p_mode text,p_id text,p_actor text,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;carrier jsonb;tuple_rows jsonb;maximum jsonb:='[]';frozen jsonb:='[]';slots jsonb:='[]';
 descriptor jsonb;item record;origin jsonb;payload jsonb;row_value jsonb;revoker text;ordinal integer:=0;
 scanned integer:=0;reads integer:=0;cost integer;scope_row jsonb;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'purpose'<>'participant' OR coalesce(p_id,'')=''
 OR p_mode NOT IN ('delete','revoke','expiry','delegation') OR p_actor IS NULL
 OR (p_mode='delegation' AND proof->>'kind'<>'delegation')
 OR (p_mode<>'delegation' AND proof->>'kind'<>'binding') THEN
  RAISE EXCEPTION 'withdrawal sequence lacks exact signed operation' USING ERRCODE='42501';END IF;
 IF p_rows IS NULL OR p_reads IS NULL OR p_rows NOT BETWEEN 1 AND 100000 OR p_reads NOT BETWEEN 1 AND 4096 THEN
  RAISE EXCEPTION 'withdrawal sequence source budget absent' USING ERRCODE='54000';END IF;
 reads:=reads+1;
 FOR carrier IN SELECT to_jsonb(b) FROM kaname.access_bindings b
  WHERE (p_mode='delegation' AND b.delegation_id=p_id AND b.revoked_at IS NULL)
   OR (p_mode<>'delegation' AND b.id=p_id) ORDER BY b.id LIMIT p_rows+1 LOOP
  scanned:=scanned+1;
  IF scanned>p_rows THEN RAISE EXCEPTION 'withdrawal carrier budget' USING ERRCODE='54000';END IF;
  revoker:=p_actor;
  IF p_mode='revoke' AND revoker='' THEN revoker:=coalesce(nullif(carrier->>'granted_by_user_id',''),'system:revoke');END IF;
  ordinal:=ordinal+1;
  origin:=jsonb_build_object('family','binding.withdrawal','mode',p_mode,'binding',carrier->>'id','effect','journal');
  maximum:=maximum||jsonb_build_array(jsonb_build_object('table','resource_journal','ordinal',ordinal,'origin',origin,'row','{}'::jsonb,'stamp','transaction'));
  -- Scope вычисляется сейчас под source/fence locks. После clock меняются
  -- только revoked_* и status, которые не участвуют в canonical scope.
  scope_row:=jsonb_build_object('resource_kind','iam_access_binding','resource_id',carrier->>'id',
   'project_id',kaname.resource_journal_project('iam_access_binding',carrier),
   'scope',kaname.resource_journal_scope('iam_access_binding',carrier),
   'event_type',CASE p_mode WHEN 'delete' THEN 'DELETED' ELSE 'UPDATED' END,
   'payload',jsonb_build_object('id',carrier->>'id'));
  descriptor:=jsonb_build_object('old',carrier,'revoker',revoker,'journal',ordinal,'row',scope_row);
  SELECT coalesce(jsonb_agg(jsonb_build_object('relation',t.relation,'object',t.object,'user',t.fga_user)
   ORDER BY t.relation,t.object,t.fga_user),'[]') INTO tuple_rows FROM (
   SELECT DISTINCT relation,object,fga_user FROM kaname.access_binding_emitted_tuples
   WHERE binding_id=carrier->>'id' ORDER BY relation,object,fga_user LIMIT p_rows-scanned+1
  ) t;
  reads:=reads+1;scanned:=scanned+jsonb_array_length(tuple_rows);
  IF scanned>p_rows OR reads>p_reads THEN RAISE EXCEPTION 'withdrawal ledger budget' USING ERRCODE='54000';END IF;
  slots:='[]';
  FOR item IN WITH numbered AS (
   SELECT value tuple,(row_number() OVER (ORDER BY value->>'relation',value->>'object',value->>'user')-1)/256 page
   FROM jsonb_array_elements(tuple_rows)
  ) SELECT page,tuple->>'object' object_name,tuple->>'user' user_name,
   jsonb_agg(tuple->>'relation' ORDER BY (tuple->>'relation') COLLATE "C") relations
   FROM numbered GROUP BY page,tuple->>'object',tuple->>'user' ORDER BY page,(tuple->>'object') COLLATE "C",(tuple->>'user') COLLATE "C"
  LOOP
   payload:=jsonb_build_object('object',item.object_name,'user',item.user_name);
   IF jsonb_array_length(item.relations)=1 THEN payload:=payload||jsonb_build_object('relation',item.relations->>0);
   ELSE payload:=payload||jsonb_build_object('relations',item.relations);END IF;
   ordinal:=ordinal+1;origin:=jsonb_build_object('family','binding.withdrawal','mode',p_mode,'binding',carrier->>'id',
    'effect','fga','page',item.page,'object',item.object_name,'user',item.user_name);
   row_value:=jsonb_build_object('event_type','fga.tuple.delete','payload',payload);
   maximum:=maximum||jsonb_build_array(jsonb_build_object('table','fga_outbox','ordinal',ordinal,'origin',origin,'row','{}'::jsonb,'stamp','decision'));
   slots:=slots||jsonb_build_array(jsonb_build_object('ordinal',ordinal,'origin',origin,'row',row_value));
  END LOOP;
  descriptor:=descriptor||jsonb_build_object('fga',slots);
  frozen:=frozen||jsonb_build_array(descriptor);
 END LOOP;
 IF p_mode<>'delegation' AND jsonb_array_length(frozen)<>1 THEN
  RAISE EXCEPTION 'withdrawal binding disappeared' USING ERRCODE='P1034';END IF;
 scanned:=scanned+jsonb_array_length(maximum);
 IF scanned>p_rows OR reads>p_reads THEN RAISE EXCEPTION 'withdrawal program budget' USING ERRCODE='54000';END IF;
 cost:=kaname._authority_sequence_reserve_v3('binding',maximum,p_reads-reads);
 PERFORM kaname._authority_sequence_freeze_v3(jsonb_build_object('kind','binding.withdrawal','mode',p_mode,'id',p_id,
  'actor',p_actor,'bindings',frozen));
 RETURN jsonb_build_object('rows',scanned,'reads',reads+cost);
END $$;

CREATE FUNCTION kaname.authority_binding_withdrawal_sequence_finalize_v3() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;proof jsonb;at_time timestamptz;chosen jsonb;withdrawal_mode text;
BEGIN
 program:=kaname._authority_sequence_store_v3();proof:=kaname.authority_protocol_attestation();
 IF program IS NULL OR proof IS NULL OR program->>'family'<>'binding'
 OR program#>>'{frozen,kind}'<>'binding.withdrawal' THEN
  RAISE EXCEPTION 'withdrawal maximum is absent' USING ERRCODE='42501';END IF;
 at_time:=(proof->>'decision_at')::timestamptz;withdrawal_mode:=program#>>'{frozen,mode}';
 IF at_time<=(program->>'staged_decision_at')::timestamptz THEN
  RAISE EXCEPTION 'withdrawal decision was not refreshed' USING ERRCODE='42501';END IF;
 -- Порядок прежнего цикла: binding position, затем journal и FGA item position.
 -- NULL-предикат сохраняет семантику прежнего IF ... THEN CONTINUE.
 WITH descriptors AS MATERIALIZED (
  SELECT e.value AS descriptor,e.position AS binding_position,e.value->'old' AS old_image
  FROM jsonb_array_elements(program#>'{frozen,bindings}') WITH ORDINALITY e(value,position)
 ), eligible AS MATERIALIZED (
  SELECT d.descriptor,d.binding_position,d.old_image FROM descriptors d
  WHERE NOT coalesce(withdrawal_mode='expiry' AND (d.old_image->>'status'<>'ACTIVE'
   OR d.old_image->>'expires_at' IS NULL OR (d.old_image->>'expires_at')::timestamptz>at_time),false)
 ), images AS MATERIALIZED (
  SELECT e.descriptor,e.binding_position,e.old_image,
   CASE WHEN withdrawal_mode<>'delete' THEN e.old_image||jsonb_build_object('status','REVOKED','revoked_at',at_time,
    'revocation_reason',CASE withdrawal_mode WHEN 'expiry' THEN 'EXPIRED' WHEN 'delegation' THEN 'DELEGATION_REVOKED' ELSE 'REVOKE' END)
    ||CASE WHEN withdrawal_mode<>'expiry' THEN jsonb_build_object('revoked_by_user_id',e.descriptor->>'revoker') ELSE '{}'::jsonb END
   ELSE NULL END AS new_image
  FROM eligible e
 ), effects AS (
  SELECT i.binding_position,0::bigint AS item_position,
   jsonb_build_object('ordinal',i.descriptor->'journal','origin',
    jsonb_build_object('table','access_bindings','operation',CASE withdrawal_mode WHEN 'delete' THEN 'DELETE' ELSE 'UPDATE' END,
     'when',CASE withdrawal_mode WHEN 'delete' THEN 'BEFORE' ELSE 'AFTER' END,'old',i.old_image,'new',i.new_image),
    'row',i.descriptor->'row') AS effect
  FROM images i
  UNION ALL
  SELECT i.binding_position,e.position,e.value FROM images i
   CROSS JOIN LATERAL jsonb_array_elements(i.descriptor->'fga') WITH ORDINALITY e(value,position)
 )
 SELECT coalesce(jsonb_agg(e.effect ORDER BY e.binding_position,e.item_position),'[]'::jsonb)
 INTO chosen FROM effects e;
 PERFORM kaname._authority_sequence_bind_v3(chosen,at_time);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_cluster_admin_preflight_v4(p_type text,p_id text,p_action text) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; at_time timestamptz; maximum jsonb;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF NOT coalesce(proof->>'kind'='cluster' AND proof->>'purpose'='participant' AND proof->>'mode'='global',false) THEN
  RAISE EXCEPTION 'cluster final decision entry required' USING ERRCODE='42501';
 END IF;
 IF p_action IS NULL OR p_action NOT IN ('grant','revoke') OR p_type IS NULL OR p_type NOT IN ('user','service_account') OR p_id IS NULL OR p_id='' OR length(p_id)>64 THEN
  RAISE EXCEPTION 'invalid cluster decision target' USING ERRCODE='22023';
 END IF;
 -- Полный native/source readset, включая scope view, группы, альтернативные
 -- roleless/role carriers, checkpoint и named holders fold-delete. Табличные
 -- locks исключают также absent-row/typed-collision phantom до Commit.
 LOCK TABLE kaname.access_binding_emitted_tuples,kaname.access_binding_subjects,
  kaname.access_binding_target_members,kaname.access_bindings,kaname.accounts,
  kaname.catalog_module,kaname.catalog_resource,kaname.catalog_verb,kaname.clusters,
  kaname.grant_delegations,kaname.group_members,kaname.groups,kaname.memberships,
  kaname.producer_source_receipt,kaname.projects,kaname.public_read_publication,
  kaname.resource_mirror,kaname.resource_parent_edge,kaname.resource_registration_pointer,
  kaname.resource_registration_retirement,kaname.resource_registration_scope,
  kaname.role_bind_role_rule,kaname.role_create_binding_rule,kaname.role_rule_ref,
  kaname.role_rule_selectors,kaname.role_selector_verbs_pending,kaname.role_verb,
  kaname.roles,kaname.service_accounts,kaname.users IN SHARE MODE;
 LOCK TABLE kaname.cluster_admin_grants,kaname.relation_fact,
  kaname.authority_policy_epoch IN SHARE ROW EXCLUSIVE MODE;
 LOCK TABLE kaname.audit_outbox,kaname.fga_outbox IN ROW EXCLUSIVE MODE;
 -- View получает собственный relation lock до часов, не только locks базовых таблиц.
 LOCK TABLE kaname.resource_scope_edge IN ACCESS SHARE MODE;
 PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam:cluster-admin-revoke:cluster_root'));
 -- SELECT FOR UPDATE чужого читателя не конфликтует с SHARE table lock.
 -- Поэтому фактические изменяемые строки ждём отдельно до decision_at.
 PERFORM id FROM kaname.cluster_admin_grants WHERE subject_type=p_type AND subject_id=p_id ORDER BY id FOR UPDATE;
 PERFORM 1 FROM kaname.relation_fact WHERE object_type='cluster' AND object_id='cluster_root'
  AND relation='system_admin' AND subject=p_type||':'||p_id FOR UPDATE;
 PERFORM id FROM kaname.clusters WHERE id='cluster_root' FOR KEY SHARE;
 PERFORM key FROM kaname.authority_policy_epoch WHERE key IN ('*',p_type||':'||p_id) ORDER BY key COLLATE "C" FOR UPDATE;
 -- Оба успешных UC всегда посылают ровно один FGA event, включая
 -- повторный Grant активному субъекту; только audit этого no-op отсутствует.
 -- Отказ native/CAS откатывает весь резерв и никогда не выбирает пустой успех.
 maximum:=jsonb_build_array(jsonb_build_object('table','fga_outbox','ordinal',1,
  'origin',jsonb_build_object('family','cluster','action',p_action,'subject_type',p_type,'subject_id',p_id),
  'row',jsonb_build_object('event_type',CASE p_action WHEN 'grant' THEN 'fga.tuple.write' ELSE 'fga.tuple.delete' END,
   'payload',jsonb_build_object('user',p_type||':'||p_id,'relation','system_admin','object','cluster:cluster_root')),
  'stamp','decision'));
 PERFORM kaname._authority_sequence_reserve_v3('cluster',maximum,16);
 at_time:=pg_catalog.clock_timestamp();
 UPDATE pg_temp.kaname_authority_attestation SET decision_at=at_time;
 PERFORM kaname._authority_sequence_select_v3(ARRAY[1],at_time);
 RETURN at_time;
END $$;

-- Старый бинарник не получает часы без нового reserved-ID контракта.
CREATE OR REPLACE FUNCTION kaname.authority_cluster_admin_preflight(p_type text,p_id text) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 RAISE EXCEPTION 'cluster final sequence contract upgrade required' USING ERRCODE='P1036';
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_preflight_body_v4(p_kind text,p_id text,p_rename boolean,p_audit text)
RETURNS TABLE(row_xmin text,row_value jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; table_name text; account_id text; sequence_id regclass;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'writer_contract' IS DISTINCT FROM '2'
 OR proof->>'purpose' IS DISTINCT FROM 'decision' OR proof->>'kind' IS DISTINCT FROM 'resource'
 OR p_id IS NULL OR p_id='' OR p_rename IS NULL OR p_audit IS NULL OR p_audit='' OR length(p_audit)>64 THEN
  RAISE EXCEPTION 'metadata preflight requires full resource decision entry' USING ERRCODE='42501';
 END IF;
 CASE p_kind WHEN 'account' THEN table_name:='accounts';
 WHEN 'project' THEN table_name:='projects';
 WHEN 'service_account' THEN table_name:='service_accounts';
 ELSE RAISE EXCEPTION 'unsupported metadata update' USING ERRCODE='22023'; END CASE;
 -- Вход уже удерживает полный набор account fences. Для project/service_account
 -- UNIQUE(account_id,name) не допускает конкурента того же ключа без того же
 -- exclusive account fence (либо GLOBAL); OLD/NEW scopes проверяет strict2 guard.
 -- Только глобально уникальное имя account требует дождаться чужого аккаунта
 -- через SRE. Description/labels и обе локальные rename-ветки берут RowExclusive.
 IF p_rename AND p_kind='account' THEN
  EXECUTE format('LOCK TABLE kaname.%I IN SHARE ROW EXCLUSIVE MODE',table_name);
 ELSE
  EXECUTE format('LOCK TABLE kaname.%I IN ROW EXCLUSIVE MODE',table_name);
 END IF;
 -- Complete direct/trigger write footprint: UPDATE target, policy+binding
 -- epochs, journal, audit and optional reconcile outbox. No tuple fold is
 -- executed by these metadata bodies; post-commit reconciliation is separate.
 LOCK TABLE kaname.audit_outbox,kaname.authority_binding_epoch,
  kaname.authority_policy_epoch,kaname.resource_journal,
  kaname.resource_reconcile_outbox IN ROW EXCLUSIVE MODE;
 FOREACH sequence_id IN ARRAY ARRAY['kaname.resource_reconcile_outbox_id_seq'::regclass] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_backend_pid()
   AND l.locktype='relation' AND l.relation=sequence_id AND l.mode='RowExclusiveLock' AND l.granted) THEN
   PERFORM nextval(sequence_id);
  END IF;
 END LOOP;
 EXECUTE format('SELECT o.xmin::text,to_jsonb(o) FROM kaname.%I o WHERE id=$1 FOR UPDATE',table_name)
  INTO STRICT row_xmin,row_value USING p_id;
 account_id:=CASE WHEN p_kind='account' THEN row_value->>'id' ELSE row_value->>'account_id' END;
 IF account_id IS NULL OR account_id='' OR
  (proof->>'mode'='accounts' AND NOT (proof->'accounts' ? account_id)) THEN
  RAISE EXCEPTION 'metadata owner changed' USING ERRCODE='40001';
 END IF;
 -- The UPDATE's epoch trigger must not discover a new physical wait after
 -- the final clock. A missing epoch is an inconsistent stage, not an INSERT.
 PERFORM scope FROM kaname.authority_binding_epoch WHERE scope='' FOR KEY SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'binding root absent' USING ERRCODE='40001'; END IF;
 PERFORM scope FROM kaname.authority_binding_epoch WHERE scope=account_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'binding owner epoch absent' USING ERRCODE='40001'; END IF;
 PERFORM pg_advisory_xact_lock(1262569298,hashtext(p_audit));
 PERFORM id FROM kaname.audit_outbox WHERE id=p_audit FOR UPDATE;
 RETURN NEXT;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_sequence_shape_v3() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE storage oid:=to_regclass('pg_temp.kaname_authority_sequence_program');
 effects oid:=to_regclass('pg_temp.kaname_authority_sequence_effects');
BEGIN
 -- Проверяется до final clock и до публикации reserved program. После этого
 -- ordinary LOGIN не может менять owner-private DDL; горячий header заново
 -- проверяет владельца, ACL, OID пары и подпись каждой транзакции.
 IF storage IS NULL OR effects IS NULL
 OR (SELECT array_agg(a.attname::text ORDER BY a.attnum) FROM pg_catalog.pg_attribute a
  WHERE a.attrelid=storage AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM
  ARRAY['singleton','backend','transaction_id','invoker_oid','nonce','family','maximum','frozen','staged_decision_at',
   'selected','unselected','decision_at','frozen_mode','effects_oid','maximum_count','selected_count']
 OR (SELECT array_agg(a.atttypid ORDER BY a.attnum) FROM pg_catalog.pg_attribute a
  WHERE a.attrelid=storage AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM
  ARRAY['boolean'::regtype::oid,'integer'::regtype::oid,'xid8'::regtype::oid,'oid'::regtype::oid,'uuid'::regtype::oid,
   'text'::regtype::oid,'jsonb'::regtype::oid,'jsonb'::regtype::oid,'timestamptz'::regtype::oid,
   'jsonb'::regtype::oid,'jsonb'::regtype::oid,'timestamptz'::regtype::oid,'text'::regtype::oid,'oid'::regtype::oid,
   'integer'::regtype::oid,'integer'::regtype::oid]
 OR (SELECT array_agg(a.attname::text ORDER BY a.attnum) FROM pg_catalog.pg_attribute a
  WHERE a.attrelid=effects AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM
  ARRAY['ordinal','nonce','table_name','reserved_id','origin','row_value','origin_digest','row_digest','selected','registered','claimed','consumed']
 OR (SELECT array_agg(a.atttypid ORDER BY a.attnum) FROM pg_catalog.pg_attribute a
  WHERE a.attrelid=effects AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM
  ARRAY['integer'::regtype::oid,'uuid'::regtype::oid,'text'::regtype::oid,'bigint'::regtype::oid,
   'jsonb'::regtype::oid,'jsonb'::regtype::oid,'bytea'::regtype::oid,'bytea'::regtype::oid,
   'boolean'::regtype::oid,'boolean'::regtype::oid,'boolean'::regtype::oid,'boolean'::regtype::oid]
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=effects AND a.attnum>0
  AND (a.attisdropped OR NOT a.attnotnull OR a.attgenerated<>''))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
  CROSS JOIN LATERAL aclexplode(a.attacl) x
  WHERE a.attrelid IN (storage,effects) AND x.grantee<>c.relowner)
 OR (SELECT count(*) FROM pg_catalog.pg_index i WHERE i.indrelid=effects)<>4
 OR (SELECT count(DISTINCT i.indkey::text) FROM pg_catalog.pg_index i WHERE i.indrelid=effects)<>4
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
  JOIN pg_catalog.pg_am a ON a.oid=c.relam WHERE i.indrelid=effects AND
  (NOT i.indisvalid OR NOT i.indisready OR NOT i.indislive OR i.indexprs IS NOT NULL OR i.indpred IS NOT NULL
   OR a.amname<>'btree' OR i.indnatts<>i.indnkeyatts
   OR NOT ((i.indisprimary AND i.indisunique AND i.indkey='1'::int2vector)
    OR (NOT i.indisprimary AND i.indisunique AND i.indkey='2 3 4'::int2vector)
    OR (NOT i.indisprimary AND NOT i.indisunique AND i.indkey IN ('2 3 7 8 1'::int2vector,'2 3 9 11 1'::int2vector)))))
 THEN RAISE EXCEPTION 'sequence private storage shape changed' USING ERRCODE='42501';END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Малый header проверяется заново при каждом обращении; compiler JSON не
-- сериализуется на горячем пути. Таблицы связаны точным OID и nonce транзакции.
-- Одна свежая проверка proof и header; результат живёт только в этом вызове.
-- Compatibility NULL не читает даже наличие private temporary storage.
CREATE FUNCTION kaname._authority_sequence_probe_v3() RETURNS TABLE(proof jsonb,header jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE storage oid;effects oid;result jsonb;owner_oid oid;relation_id oid;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL THEN RETURN NEXT;RETURN;END IF;
 storage:=to_regclass('pg_temp.kaname_authority_sequence_program');
 IF storage IS NULL THEN RETURN NEXT;RETURN;END IF;
 effects:=to_regclass('pg_temp.kaname_authority_sequence_effects');
 SELECT oid INTO STRICT owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
 FOREACH relation_id IN ARRAY ARRAY[storage,effects] LOOP
  IF relation_id IS NULL OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=relation_id
   AND c.relowner=owner_oid AND c.relpersistence='t' AND c.relkind='r')
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c
   CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
   WHERE c.oid=relation_id AND a.grantee<>owner_oid) THEN
   RAISE EXCEPTION 'untrusted sequence program storage' USING ERRCODE='42501';END IF;
 END LOOP;
 SELECT jsonb_build_object('backend',s.backend,'transaction_id',s.transaction_id,
  'invoker_oid',s.invoker_oid,'nonce',s.nonce,'family',s.family,'effects_oid',s.effects_oid,
  'maximum_count',s.maximum_count,'selected_count',s.selected_count,
  'selected',CASE WHEN s.selected_count IS NULL THEN NULL ELSE '[]'::jsonb END,
  'frozen',jsonb_build_object('mode',s.frozen_mode)) INTO result
 FROM pg_temp.kaname_authority_sequence_program s WHERE s.singleton;
 IF result IS NULL THEN RETURN NEXT;RETURN;END IF;
 IF result->>'backend' IS DISTINCT FROM proof->>'backend'
 OR result->>'transaction_id' IS DISTINCT FROM proof->>'transaction_id'
 OR result->>'invoker_oid' IS DISTINCT FROM proof->>'invoker_oid'
 OR result->>'nonce' IS DISTINCT FROM proof->>'nonce'
 OR (result->>'maximum_count')::integer NOT BETWEEN 0 AND 100000
 OR ((result->>'selected_count') IS NOT NULL AND
  (result->>'selected_count')::integer NOT BETWEEN 0 AND (result->>'maximum_count')::integer)
 OR (result->>'effects_oid')::oid IS DISTINCT FROM effects THEN
  RAISE EXCEPTION 'sequence program transaction changed' USING ERRCODE='42501';END IF;
 header:=result;
 RETURN NEXT;
END $$;
CREATE FUNCTION kaname._authority_sequence_header_v3() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;result jsonb;
BEGIN
 SELECT q.proof,q.header INTO STRICT proof,result FROM kaname._authority_sequence_probe_v3() q;
 IF proof IS NULL THEN RAISE EXCEPTION 'sequence program requires signed transaction' USING ERRCODE='42501';END IF;
 RETURN result;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_sequence_publish_v3(p_chosen jsonb) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE header jsonb;changed integer;
BEGIN
 header:=kaname._authority_sequence_header_v3();
 IF header IS NULL OR header->'selected'<>'null'::jsonb
 OR jsonb_typeof(p_chosen) IS DISTINCT FROM 'array'
 OR EXISTS(SELECT 1 FROM pg_temp.kaname_authority_sequence_effects e
  WHERE e.nonce<>(header->>'nonce')::uuid OR e.selected OR e.registered OR e.claimed OR e.consumed)
 OR (SELECT count(*) FROM pg_temp.kaname_authority_sequence_effects)<>(header->>'maximum_count')::integer THEN
  RAISE EXCEPTION 'sequence selected storage changed before finalization' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_authority_sequence_effects e SET selected=true,
  origin=c.value->'origin',row_value=c.value->'row',
  origin_digest=sha256(convert_to((c.value->'origin')::text,'UTF8')),
  row_digest=sha256(convert_to((c.value->'row')::text,'UTF8'))
 FROM jsonb_array_elements(p_chosen) c(value)
 WHERE e.ordinal=(c.value->>'ordinal')::integer AND e.nonce=(header->>'nonce')::uuid
 AND e.table_name=c.value->>'table' AND e.reserved_id=(c.value->>'reserved_id')::bigint;
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed<>jsonb_array_length(p_chosen) THEN
  RAISE EXCEPTION 'sequence selection escaped reserved slots' USING ERRCODE='42501';END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Только закрытые owner compilers используют slots. Runtime не передаёт ни
-- максимум, ни frozen program, ни выбранные payload/IDs. Empty row здесь —
-- private резерв возможности, не INSERT/dummy event в публичную таблицу.
CREATE FUNCTION kaname._authority_sequence_freeze_v3(p_frozen jsonb) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;
BEGIN
 program:=kaname._authority_sequence_store_v3();
 IF program IS NULL OR program->'selected'<>'null'::jsonb OR program->'frozen'<>'{}'::jsonb
 OR jsonb_typeof(p_frozen) IS DISTINCT FROM 'object' OR p_frozen='{}'::jsonb
 OR octet_length(p_frozen::text)>67108864 THEN
  RAISE EXCEPTION 'sequence frozen compiler output invalid or repeated' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_authority_sequence_program SET frozen=p_frozen,frozen_mode=p_frozen->>'mode';
END $$;

-- p_chosen содержит только результаты private family finalizer. Он выбирает
-- slot и exact origin/row из frozen command alternatives; здесь новые ID не
-- выделяются и никакая пользовательская таблица не читается.
CREATE FUNCTION kaname._authority_sequence_bind_v3(p_chosen jsonb,p_at timestamptz) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;maximum_value jsonb;maximum_count integer;actual jsonb;slot jsonb;
 chosen jsonb;discarded jsonb;ordinal_membership jsonb;distinct_ordinals integer;n integer;
BEGIN
 program:=kaname._authority_sequence_store_v3();
 maximum_value:=program->'maximum';maximum_count:=jsonb_array_length(maximum_value);
 IF program IS NULL OR program->'selected'<>'null'::jsonb OR program->'frozen'='{}'::jsonb
 OR jsonb_typeof(p_chosen) IS DISTINCT FROM 'array' OR p_at IS NULL
 OR jsonb_array_length(p_chosen)>maximum_count THEN
  RAISE EXCEPTION 'sequence binding lacks frozen maximum' USING ERRCODE='42501';END IF;
 -- Проверяем каждый исходный descriptor; maximum извлечён из cold store один раз.
 FOR actual IN SELECT e.value FROM jsonb_array_elements(p_chosen) e(value) LOOP
  n:=(actual->>'ordinal')::integer;
  IF n IS NULL OR n<1 OR n>maximum_count
  OR actual-ARRAY['ordinal','origin','row']<>'{}'::jsonb
  OR jsonb_typeof(actual->'origin') IS DISTINCT FROM 'object'
  OR jsonb_typeof(actual->'row') IS DISTINCT FROM 'object'
  OR actual->'row' ? 'created_at' OR actual->'row' ? 'id' OR actual->'row' ? 'sequence_no' THEN
   RAISE EXCEPTION 'sequence binding extends or repeats frozen slots' USING ERRCODE='42501';END IF;
  slot:=maximum_value->(n-1);
  IF slot->>'ordinal' IS DISTINCT FROM n::text OR slot->'row'<>'{}'::jsonb THEN
   RAISE EXCEPTION 'sequence binding selected a non-slot descriptor' USING ERRCODE='42501';END IF;
 END LOOP;
 -- Нормализованные integer ordinals выявляют и повтор 1/"01" до publish.
 SELECT coalesce(jsonb_object_agg(((e.value->>'ordinal')::integer)::text,true),'{}'::jsonb),
  count(DISTINCT (e.value->>'ordinal')::integer)::integer
 INTO ordinal_membership,distinct_ordinals FROM jsonb_array_elements(p_chosen) e(value);
 IF distinct_ordinals<>jsonb_array_length(p_chosen) THEN
  RAISE EXCEPTION 'sequence binding extends or repeats frozen slots' USING ERRCODE='42501';END IF;
 WITH entries AS MATERIALIZED (
  SELECT e.value,e.position,maximum_value->((e.value->>'ordinal')::integer-1) AS slot_value
  FROM jsonb_array_elements(p_chosen) WITH ORDINALITY e(value,position)
 )
 SELECT coalesce(jsonb_agg(e.slot_value||jsonb_build_object('origin',e.value->'origin',
   'row',(e.value->'row')||jsonb_build_object('created_at',
    CASE e.slot_value->>'stamp' WHEN 'transaction' THEN transaction_timestamp() ELSE p_at END))
   ORDER BY e.position),'[]'::jsonb)
 INTO chosen FROM entries e;
 SELECT coalesce(jsonb_agg(e.value->'ordinal' ORDER BY e.position),'[]'::jsonb)
 INTO discarded FROM jsonb_array_elements(maximum_value) WITH ORDINALITY e(value,position)
 WHERE NOT coalesce(jsonb_typeof(e.value->'ordinal')='number'
  AND ordinal_membership ? ((e.value->>'ordinal')::integer)::text,false);
 PERFORM kaname._authority_sequence_publish_v3(chosen);
 UPDATE pg_temp.kaname_authority_sequence_program SET selected=chosen,unselected=discarded,decision_at=p_at,selected_count=jsonb_array_length(chosen);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- SOURCE dependency: два публичных zero-argument DEFAULT wrappers возвращают
-- только очередной ID. Они не принимают scope, effect program или private proof.
CREATE FUNCTION kaname._authority_sequence_default_v3(p_table text) RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;program jsonb;entry jsonb;sequence_id oid;table_id oid;namespace integer;identifier bigint;invoker oid;
BEGIN
 CASE p_table
 WHEN 'resource_journal' THEN table_id:='kaname.resource_journal'::regclass;
  sequence_id:='kaname.resource_journal_sequence_no_seq'::regclass;namespace:=1262569304;
 WHEN 'fga_outbox' THEN table_id:='kaname.fga_outbox'::regclass;
  sequence_id:='kaname.fga_outbox_id_seq'::regclass;namespace:=1262569305;
 ELSE RAISE EXCEPTION 'unsupported sequence default' USING ERRCODE='42501';END CASE;
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL THEN
  SELECT oid INTO STRICT invoker FROM pg_catalog.pg_roles
   WHERE rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
 ELSE invoker:=(proof->>'invoker_oid')::oid;END IF;
 IF NOT has_sequence_privilege(invoker,sequence_id,'USAGE,UPDATE')
 OR NOT has_table_privilege(invoker,table_id,'INSERT') THEN
  RAISE EXCEPTION 'sequence default lacks original privileges' USING ERRCODE='42501';END IF;
 IF proof IS NOT NULL THEN
 DECLARE storage oid;effects oid;result jsonb;owner_oid oid;relation_id oid;
 BEGIN
  -- Повторяем custody READS на прежнем header locus. Proof свежий и локален
  -- этой invocation; между его проверкой и этим блоком нет DML/callback/wait.
  IF proof IS NULL THEN RAISE EXCEPTION 'sequence program requires signed transaction' USING ERRCODE='42501';END IF;
  program:=NULL;
  storage:=to_regclass('pg_temp.kaname_authority_sequence_program');
  IF storage IS NOT NULL THEN
 effects:=to_regclass('pg_temp.kaname_authority_sequence_effects');
 SELECT oid INTO STRICT owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
 FOREACH relation_id IN ARRAY ARRAY[storage,effects] LOOP
  IF relation_id IS NULL OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=relation_id
   AND c.relowner=owner_oid AND c.relpersistence='t' AND c.relkind='r')
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c
   CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
   WHERE c.oid=relation_id AND a.grantee<>owner_oid) THEN
   RAISE EXCEPTION 'untrusted sequence program storage' USING ERRCODE='42501';END IF;
 END LOOP;
 SELECT jsonb_build_object('backend',s.backend,'transaction_id',s.transaction_id,
  'invoker_oid',s.invoker_oid,'nonce',s.nonce,'family',s.family,'effects_oid',s.effects_oid,
  'maximum_count',s.maximum_count,'selected_count',s.selected_count,
  'selected',CASE WHEN s.selected_count IS NULL THEN NULL ELSE '[]'::jsonb END,
  'frozen',jsonb_build_object('mode',s.frozen_mode)) INTO result
 FROM pg_temp.kaname_authority_sequence_program s WHERE s.singleton;
 IF result IS NOT NULL THEN
 IF result->>'backend' IS DISTINCT FROM proof->>'backend'
 OR result->>'transaction_id' IS DISTINCT FROM proof->>'transaction_id'
 OR result->>'invoker_oid' IS DISTINCT FROM proof->>'invoker_oid'
 OR result->>'nonce' IS DISTINCT FROM proof->>'nonce'
 OR (result->>'maximum_count')::integer NOT BETWEEN 0 AND 100000
 OR ((result->>'selected_count') IS NOT NULL AND
  (result->>'selected_count')::integer NOT BETWEEN 0 AND (result->>'maximum_count')::integer)
 OR (result->>'effects_oid')::oid IS DISTINCT FROM effects THEN
  RAISE EXCEPTION 'sequence program transaction changed' USING ERRCODE='42501';END IF;
 END IF;
   program:=result;
  END IF;
 END;
 END IF;
 IF program IS NOT NULL THEN
  IF p_table='resource_journal' THEN
   -- Journal emit передаёт exact actual TG origin и получает ID через private
   -- matcher. Прямой INSERT не может заменить этот путь вызовом DEFAULT.
   RAISE EXCEPTION 'prepared journal requires exact trigger origin' USING ERRCODE='42501';END IF;
  IF jsonb_typeof(program->'selected') IS DISTINCT FROM 'array' THEN
   RAISE EXCEPTION 'sequence body entered before final selection' USING ERRCODE='42501';END IF;
  SELECT jsonb_build_object('origin',e.origin,'row',e.row_value) INTO entry
   FROM pg_temp.kaname_authority_sequence_effects e
   WHERE e.nonce=(program->>'nonce')::uuid AND e.table_name=p_table AND e.selected AND NOT e.claimed
   ORDER BY e.ordinal LIMIT 1;
  IF entry IS NULL THEN RAISE EXCEPTION 'sequence program exhausted' USING ERRCODE='42501';END IF;
  -- Точный claim на прежнем месте; отдельный ABI claim сохраняет свежую проверку.

DECLARE program jsonb;matches integer;matched_ordinal integer;identifier bigint;key_namespace integer;changed integer;
 p_origin jsonb:=entry->'origin';p_row jsonb:=entry->'row';
BEGIN
 DECLARE storage oid;effects oid;result jsonb;owner_oid oid;relation_id oid;
 BEGIN
  -- Повторяем custody READS на прежнем header locus. Proof свежий и локален
  -- этой invocation; между его проверкой и этим блоком нет DML/callback/wait.
  IF proof IS NULL THEN RAISE EXCEPTION 'sequence program requires signed transaction' USING ERRCODE='42501';END IF;
  program:=NULL;
  storage:=to_regclass('pg_temp.kaname_authority_sequence_program');
  IF storage IS NOT NULL THEN
 effects:=to_regclass('pg_temp.kaname_authority_sequence_effects');
 SELECT oid INTO STRICT owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
 FOREACH relation_id IN ARRAY ARRAY[storage,effects] LOOP
  IF relation_id IS NULL OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=relation_id
   AND c.relowner=owner_oid AND c.relpersistence='t' AND c.relkind='r')
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c
   CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
   WHERE c.oid=relation_id AND a.grantee<>owner_oid) THEN
   RAISE EXCEPTION 'untrusted sequence program storage' USING ERRCODE='42501';END IF;
 END LOOP;
 SELECT jsonb_build_object('backend',s.backend,'transaction_id',s.transaction_id,
  'invoker_oid',s.invoker_oid,'nonce',s.nonce,'family',s.family,'effects_oid',s.effects_oid,
  'maximum_count',s.maximum_count,'selected_count',s.selected_count,
  'selected',CASE WHEN s.selected_count IS NULL THEN NULL ELSE '[]'::jsonb END,
  'frozen',jsonb_build_object('mode',s.frozen_mode)) INTO result
 FROM pg_temp.kaname_authority_sequence_program s WHERE s.singleton;
 IF result IS NOT NULL THEN
 IF result->>'backend' IS DISTINCT FROM proof->>'backend'
 OR result->>'transaction_id' IS DISTINCT FROM proof->>'transaction_id'
 OR result->>'invoker_oid' IS DISTINCT FROM proof->>'invoker_oid'
 OR result->>'nonce' IS DISTINCT FROM proof->>'nonce'
 OR (result->>'maximum_count')::integer NOT BETWEEN 0 AND 100000
 OR ((result->>'selected_count') IS NOT NULL AND
  (result->>'selected_count')::integer NOT BETWEEN 0 AND (result->>'maximum_count')::integer)
 OR (result->>'effects_oid')::oid IS DISTINCT FROM effects THEN
  RAISE EXCEPTION 'sequence program transaction changed' USING ERRCODE='42501';END IF;
 END IF;
   program:=result;
  END IF;
 END;
 IF program IS NULL OR jsonb_typeof(program->'selected') IS DISTINCT FROM 'array'
 OR p_table NOT IN ('resource_journal','fga_outbox') OR p_table IS NULL THEN
  RAISE EXCEPTION 'final sequence program missing' USING ERRCODE='42501';END IF;
 SELECT count(*)::integer,min(e.ordinal) INTO matches,matched_ordinal
 FROM pg_temp.kaname_authority_sequence_effects e
 WHERE e.nonce=(program->>'nonce')::uuid AND e.table_name=p_table AND e.selected AND NOT e.claimed
  AND e.origin_digest=sha256(convert_to(p_origin::text,'UTF8')) AND e.row_digest=sha256(convert_to(p_row::text,'UTF8'))
  AND e.origin=p_origin AND e.row_value=p_row;
 IF matches<>1 THEN RAISE EXCEPTION 'sequence origin or multiplicity differs from selected program' USING ERRCODE='42501';END IF;
 SELECT e.reserved_id INTO STRICT identifier FROM pg_temp.kaname_authority_sequence_effects e
  WHERE e.nonce=(program->>'nonce')::uuid AND e.ordinal=matched_ordinal;
 key_namespace:=CASE p_table WHEN 'resource_journal' THEN 1262569304 ELSE 1262569305 END;
 PERFORM kaname._authority_resource_preheld_key_v2(key_namespace,identifier::text,true);
 UPDATE pg_temp.kaname_authority_sequence_effects e SET claimed=true
  WHERE e.nonce=(program->>'nonce')::uuid AND e.ordinal=matched_ordinal AND e.selected AND NOT e.claimed;
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed<>1 THEN RAISE EXCEPTION 'sequence origin or multiplicity differs from selected program' USING ERRCODE='42501';END IF;
 RETURN identifier;
END;
 END IF;
 IF proof IS NOT NULL AND ((proof->>'consumer_finalized'='true' AND proof->>'writer_contract'='2') OR kaname._authority_sequence_expected_v3())
 AND NOT kaname._authority_sequence_excluded_v3(table_id) THEN
  RAISE EXCEPTION 'prepared Resource sequence reservation absent' USING ERRCODE='42501';END IF;
 -- Обычный INSERT уже держит RX таблицы; поэтому key не предшествует
 -- конфликтующему relation wait. Точная прежняя EXCLUSIVE preflight (Invite)
 -- исключает других RX производителей физически и не требует нового key.
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid()
  AND locktype='relation' AND relation=table_id AND granted
  AND mode IN ('RowExclusiveLock','ShareRowExclusiveLock','ExclusiveLock','AccessExclusiveLock')) THEN
  RAISE EXCEPTION 'sequence allocation requires actual INSERT relation lock' USING ERRCODE='42501';END IF;
 identifier:=nextval(sequence_id);
 IF NOT kaname._authority_sequence_excluded_v3(table_id) THEN
  PERFORM pg_advisory_xact_lock(namespace,hashtext(identifier::text));
 END IF;
 RETURN identifier;
END $$;

CREATE FUNCTION kaname.authority_resource_journal_id_v3() RETURNS bigint
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT kaname._authority_sequence_default_v3('resource_journal');
$$;
CREATE FUNCTION kaname.authority_fga_outbox_id_v3() RETURNS bigint
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT kaname._authority_sequence_default_v3('fga_outbox');
$$;

CREATE FUNCTION kaname.authority_sequence_program_applied_v3() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;program jsonb;row_value jsonb;identifier bigint;
BEGIN
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME NOT IN ('resource_journal','fga_outbox')
 OR TG_OP<>'INSERT' OR TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' THEN
  RAISE EXCEPTION 'sequence applied trigger graph changed' USING ERRCODE='42501';END IF;
 SELECT q.proof,q.header INTO STRICT proof,program FROM kaname._authority_sequence_probe_v3() q;
 IF proof IS NULL THEN RETURN NULL;END IF;
 IF program IS NULL THEN RETURN NULL;END IF;
 row_value:=to_jsonb(NEW);
 IF TG_TABLE_NAME='resource_journal' THEN
  identifier:=(row_value->>'sequence_no')::bigint;row_value:=row_value-'sequence_no';
 ELSE identifier:=(row_value->>'id')::bigint;row_value:=row_value-'id';END IF;
 -- NEW conversion и graph/NULL guards уже выполнены в исходном порядке.

DECLARE program jsonb;changed integer;
 p_table text:=TG_TABLE_NAME;p_identifier bigint:=identifier;p_row jsonb:=row_value;
BEGIN
 DECLARE storage oid;effects oid;result jsonb;owner_oid oid;relation_id oid;
 BEGIN
  -- Повторяем custody READS на прежнем header locus. Proof свежий и локален
  -- этой invocation; между его проверкой и этим блоком нет DML/callback/wait.
  IF proof IS NULL THEN RAISE EXCEPTION 'sequence program requires signed transaction' USING ERRCODE='42501';END IF;
  program:=NULL;
  storage:=to_regclass('pg_temp.kaname_authority_sequence_program');
  IF storage IS NOT NULL THEN
 effects:=to_regclass('pg_temp.kaname_authority_sequence_effects');
 SELECT oid INTO STRICT owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
 FOREACH relation_id IN ARRAY ARRAY[storage,effects] LOOP
  IF relation_id IS NULL OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=relation_id
   AND c.relowner=owner_oid AND c.relpersistence='t' AND c.relkind='r')
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c
   CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
   WHERE c.oid=relation_id AND a.grantee<>owner_oid) THEN
   RAISE EXCEPTION 'untrusted sequence program storage' USING ERRCODE='42501';END IF;
 END LOOP;
 SELECT jsonb_build_object('backend',s.backend,'transaction_id',s.transaction_id,
  'invoker_oid',s.invoker_oid,'nonce',s.nonce,'family',s.family,'effects_oid',s.effects_oid,
  'maximum_count',s.maximum_count,'selected_count',s.selected_count,
  'selected',CASE WHEN s.selected_count IS NULL THEN NULL ELSE '[]'::jsonb END,
  'frozen',jsonb_build_object('mode',s.frozen_mode)) INTO result
 FROM pg_temp.kaname_authority_sequence_program s WHERE s.singleton;
 IF result IS NOT NULL THEN
 IF result->>'backend' IS DISTINCT FROM proof->>'backend'
 OR result->>'transaction_id' IS DISTINCT FROM proof->>'transaction_id'
 OR result->>'invoker_oid' IS DISTINCT FROM proof->>'invoker_oid'
 OR result->>'nonce' IS DISTINCT FROM proof->>'nonce'
 OR (result->>'maximum_count')::integer NOT BETWEEN 0 AND 100000
 OR ((result->>'selected_count') IS NOT NULL AND
  (result->>'selected_count')::integer NOT BETWEEN 0 AND (result->>'maximum_count')::integer)
 OR (result->>'effects_oid')::oid IS DISTINCT FROM effects THEN
  RAISE EXCEPTION 'sequence program transaction changed' USING ERRCODE='42501';END IF;
 END IF;
   program:=result;
  END IF;
 END;
 IF program IS NULL OR jsonb_typeof(program->'selected') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'sequence applied without selected program' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_authority_sequence_effects e SET consumed=true
 WHERE e.nonce=(program->>'nonce')::uuid AND e.table_name=p_table AND e.reserved_id=p_identifier
  AND e.selected AND e.claimed AND NOT e.consumed
  AND e.row_digest=sha256(convert_to(p_row::text,'UTF8')) AND e.row_value=p_row;
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed<>1 THEN RAISE EXCEPTION 'sequence applied ID replay or foreign row' USING ERRCODE='42501';END IF;
END;
 RETURN NULL;
END $$;

CREATE FUNCTION kaname.authority_sequence_program_completion_v3() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_TABLE_SCHEMA NOT LIKE 'pg_temp_%' OR TG_TABLE_NAME<>'kaname_authority_sequence_program'
 OR TG_OP<>'INSERT' OR TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW'
 OR TG_RELID IS DISTINCT FROM to_regclass('pg_temp.kaname_authority_sequence_program')
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=TG_RELID AND relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)) THEN
  RAISE EXCEPTION 'sequence completion trigger graph changed' USING ERRCODE='42501';END IF;
 PERFORM kaname._authority_sequence_complete_v3();RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Prepared preflight ставит owner-private обязанность закрыть программу.
-- Старый binary не может обойти новый final-clock ABI простым отсутствием
-- sequence store; обычный compatibility без prepared preflight её не создаёт.
CREATE FUNCTION kaname._authority_sequence_expect_v3(p_family text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;storage oid;owner_oid oid;item record;actual jsonb;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR p_family NOT IN ('binding','role') OR p_family IS NULL THEN RAISE EXCEPTION 'invalid sequence expectation' USING ERRCODE='42501';END IF;
 SELECT oid INTO STRICT owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
 storage:=to_regclass('pg_temp.kaname_sequence_expectation');
 IF storage IS NULL THEN
  CREATE TEMP TABLE kaname_sequence_expectation(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),family text NOT NULL,
   backend integer NOT NULL,transaction_id text NOT NULL,invoker_oid oid NOT NULL,nonce text NOT NULL) ON COMMIT DROP;
  REVOKE ALL ON pg_temp.kaname_sequence_expectation FROM PUBLIC;
  FOR item IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE c.oid='pg_temp.kaname_sequence_expectation'::regclass AND a.grantee<>owner_oid LOOP
   EXECUTE format('REVOKE ALL ON pg_temp.kaname_sequence_expectation FROM %I',item.rolname);
  END LOOP;
  CREATE CONSTRAINT TRIGGER authority_sequence_expectation_complete_v3 AFTER INSERT ON pg_temp.kaname_sequence_expectation
   DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION kaname.authority_sequence_expectation_complete_v3();
  INSERT INTO pg_temp.kaname_sequence_expectation(family,backend,transaction_id,invoker_oid,nonce)
   VALUES(p_family,(proof->>'backend')::integer,proof->>'transaction_id',(proof->>'invoker_oid')::oid,proof->>'nonce');
  RETURN;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=storage AND c.relowner=owner_oid AND c.relpersistence='t' AND c.relkind='r') THEN
  RAISE EXCEPTION 'untrusted sequence expectation' USING ERRCODE='42501';END IF;
 SELECT to_jsonb(e) INTO STRICT actual FROM pg_temp.kaname_sequence_expectation e WHERE singleton;
 IF actual->>'family' IS DISTINCT FROM p_family OR actual->>'backend' IS DISTINCT FROM proof->>'backend'
 OR actual->>'transaction_id' IS DISTINCT FROM proof->>'transaction_id' OR actual->>'invoker_oid' IS DISTINCT FROM proof->>'invoker_oid'
 OR actual->>'nonce' IS DISTINCT FROM proof->>'nonce' THEN RAISE EXCEPTION 'sequence expectation changed' USING ERRCODE='42501';END IF;
END $$;

CREATE FUNCTION kaname._authority_sequence_expected_v3() RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE storage oid;proof jsonb;item jsonb;owner_oid oid;
BEGIN
 storage:=to_regclass('pg_temp.kaname_sequence_expectation');IF storage IS NULL THEN RETURN false;END IF;
 proof:=kaname.authority_protocol_attestation();
 SELECT oid INTO STRICT owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
 IF proof IS NULL OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=storage AND c.relowner=owner_oid AND c.relpersistence='t' AND c.relkind='r')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE c.oid=storage AND a.grantee<>owner_oid) THEN
  RAISE EXCEPTION 'untrusted sequence expectation proof/storage' USING ERRCODE='42501';END IF;
 SELECT to_jsonb(e) INTO STRICT item FROM pg_temp.kaname_sequence_expectation e WHERE singleton;
 IF item->>'backend' IS DISTINCT FROM proof->>'backend' OR item->>'transaction_id' IS DISTINCT FROM proof->>'transaction_id'
 OR item->>'invoker_oid' IS DISTINCT FROM proof->>'invoker_oid' OR item->>'nonce' IS DISTINCT FROM proof->>'nonce' THEN
  RAISE EXCEPTION 'sequence expectation lifetime changed' USING ERRCODE='42501';END IF;
 RETURN true;
END $$;

CREATE FUNCTION kaname.authority_sequence_expectation_complete_v3() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;
BEGIN
 IF TG_RELID IS DISTINCT FROM to_regclass('pg_temp.kaname_sequence_expectation') OR TG_WHEN<>'AFTER' OR TG_OP<>'INSERT'
 OR TG_LEVEL<>'ROW' OR NOT kaname._authority_sequence_expected_v3() THEN
  RAISE EXCEPTION 'sequence expectation completion graph changed' USING ERRCODE='42501';END IF;
 program:=kaname._authority_sequence_header_v3();
 IF program IS NULL OR program->>'family' IS DISTINCT FROM NEW.family THEN
  RAISE EXCEPTION 'prepared caller omitted sequence program' USING ERRCODE='P1036';END IF;
 PERFORM kaname._authority_sequence_complete_v3();RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.resource_journal_emit() RETURNS trigger
  LANGUAGE plpgsql AS $$
DECLARE
  v_reserved bigint;
  v_kind  text := TG_ARGV[0];
  v_event text;
  v_json  jsonb;
BEGIN
  IF TG_OP = 'DELETE' THEN
    v_event := 'DELETED';
    v_json  := to_jsonb(OLD);
  ELSIF TG_OP = 'UPDATE' THEN
    v_event := 'UPDATED';
    v_json  := to_jsonb(NEW);
  ELSE
    v_event := 'CREATED';
    v_json  := to_jsonb(NEW);
  END IF;

  v_reserved:=kaname.authority_prepared_journal_value_v3(jsonb_build_object('table',TG_TABLE_NAME,'operation',TG_OP,'when',TG_WHEN,'old',CASE WHEN TG_OP='INSERT' THEN NULL ELSE to_jsonb(OLD) END,'new',CASE WHEN TG_OP='DELETE' THEN NULL ELSE to_jsonb(NEW) END),jsonb_build_object('resource_kind',v_kind,'resource_id',v_json->>'id','project_id',kaname.resource_journal_project(v_kind, v_json),'scope',kaname.resource_journal_scope(v_kind, v_json),'event_type',v_event,'payload',jsonb_build_object('id', v_json->>'id')));
  IF v_reserved IS NULL THEN
  INSERT INTO kaname.resource_journal
    (resource_kind, resource_id, project_id, scope, event_type, payload)
  VALUES (
    v_kind,
    v_json->>'id',
    kaname.resource_journal_project(v_kind, v_json),
    kaname.resource_journal_scope(v_kind, v_json),
    v_event,
    jsonb_build_object('id', v_json->>'id'));
  ELSE
  INSERT INTO kaname.resource_journal
    (sequence_no, resource_kind, resource_id, project_id, scope, event_type, payload)
  VALUES (v_reserved,
    v_kind,
    v_json->>'id',
    kaname.resource_journal_project(v_kind, v_json),
    kaname.resource_journal_scope(v_kind, v_json),
    v_event,
    jsonb_build_object('id', v_json->>'id'));
  END IF;

  -- BEFORE-триггер, вернувший NULL, ОТМЕНИЛ БЫ снятие. AFTER-триггеру возврат
  -- безразличен, и NULL там — обычная форма.
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION kaname.resource_journal_emit_member() RETURNS trigger
  LANGUAGE plpgsql AS $$
DECLARE
  v_reserved bigint;
  v_kind   text := TG_ARGV[0];
  v_col    text := TG_ARGV[1];
  v_table  text := TG_ARGV[2];
  v_row    jsonb;
  v_owner  text;
  v_ownrow jsonb;
BEGIN
  v_row := CASE WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
  v_owner := v_row->>v_col;
  IF COALESCE(v_owner, '') = '' THEN
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NULL END;
  END IF;

  EXECUTE format('SELECT to_jsonb(t) FROM kaname.%I t WHERE t.id = $1', v_table)
    INTO v_ownrow USING v_owner;

  -- Владельца уже нет: его собственное снятие эмитится своим триггером, а состав
  -- уносит каскад. Второе событие о том же снятии было бы дублем.
  IF v_ownrow IS NULL THEN
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NULL END;
  END IF;

  v_reserved:=kaname.authority_prepared_journal_value_v3(jsonb_build_object('table',TG_TABLE_NAME,'operation',TG_OP,'when',TG_WHEN,'old',CASE WHEN TG_OP='INSERT' THEN NULL ELSE to_jsonb(OLD) END,'new',CASE WHEN TG_OP='DELETE' THEN NULL ELSE to_jsonb(NEW) END),jsonb_build_object('resource_kind',v_kind,'resource_id',v_owner,'project_id',kaname.resource_journal_project(v_kind, v_ownrow),'scope',kaname.resource_journal_scope(v_kind, v_ownrow),'event_type','UPDATED','payload',jsonb_build_object('id', v_owner)));
  IF v_reserved IS NULL THEN
  INSERT INTO kaname.resource_journal
    (resource_kind, resource_id, project_id, scope, event_type, payload)
  VALUES (
    v_kind,
    v_owner,
    kaname.resource_journal_project(v_kind, v_ownrow),
    kaname.resource_journal_scope(v_kind, v_ownrow),
    'UPDATED',
    jsonb_build_object('id', v_owner));
  ELSE
  INSERT INTO kaname.resource_journal
    (sequence_no, resource_kind, resource_id, project_id, scope, event_type, payload)
  VALUES (v_reserved,
    v_kind,
    v_owner,
    kaname.resource_journal_project(v_kind, v_ownrow),
    kaname.resource_journal_scope(v_kind, v_ownrow),
    'UPDATED',
    jsonb_build_object('id', v_owner));
  END IF;

  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NULL END;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Никакой caller JSON не подтверждает TG origin сам по себе. Только этот
-- owner-owned trigger читает настоящие OLD/NEW из actual source statement.
-- Отдельный INVOKER emitter сохраняет прежние ACL и канонический scope.
CREATE FUNCTION kaname.authority_sequence_origin_v3() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;program jsonb;actual_origin jsonb;entry jsonb;matched_ordinal integer;matches integer;
BEGIN
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME NOT IN ('accounts','projects','users','groups',
  'service_accounts','roles','access_bindings','group_members','memberships','access_binding_subjects')
 OR TG_OP NOT IN ('INSERT','UPDATE','DELETE') OR TG_LEVEL<>'ROW' THEN
  RAISE EXCEPTION 'sequence origin trigger escaped fixed source graph' USING ERRCODE='42501';END IF;
 SELECT q.proof,q.header INTO STRICT proof,program FROM kaname._authority_sequence_probe_v3() q;
 IF program IS NOT NULL THEN
  IF jsonb_typeof(program->'selected') IS DISTINCT FROM 'array' THEN
   RAISE EXCEPTION 'journal source mutation before sequence finalization' USING ERRCODE='42501';END IF;
  actual_origin:=jsonb_build_object('table',TG_TABLE_NAME,'operation',TG_OP,'when',TG_WHEN,
   'old',CASE WHEN TG_OP='INSERT' THEN NULL ELSE to_jsonb(OLD) END,
   'new',CASE WHEN TG_OP='DELETE' THEN NULL ELSE to_jsonb(NEW) END);
  SELECT count(*)::integer,min(e.ordinal) INTO matches,matched_ordinal
  FROM pg_temp.kaname_authority_sequence_effects e
  WHERE e.nonce=(program->>'nonce')::uuid AND e.table_name='resource_journal' AND e.selected
   AND e.origin_digest=sha256(convert_to(actual_origin::text,'UTF8')) AND e.origin=actual_origin AND NOT e.registered;
  IF matches>1 THEN RAISE EXCEPTION 'ambiguous journal source ordinal' USING ERRCODE='42501';END IF;
  IF matches=1 THEN
   UPDATE pg_temp.kaname_authority_sequence_effects e SET registered=true
    WHERE e.nonce=(program->>'nonce')::uuid AND e.ordinal=matched_ordinal AND NOT e.registered;
  END IF;
  -- Отсутствующий owner после FK cascade штатно не эмитит member event.
  -- Если emitter всё же попробует event без descriptor, getter откажет.
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END $$;

CREATE FUNCTION kaname.authority_prepared_journal_value_v3(p_origin jsonb,p_row jsonb)
RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;program jsonb;matches integer;matched_ordinal integer;actual jsonb;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NOT NULL THEN program:=kaname._authority_sequence_header_v3();END IF;
 IF program IS NULL THEN RETURN kaname.authority_resource_crud_journal_value_v3(p_origin,p_row);END IF;
 IF pg_trigger_depth()<1 OR jsonb_typeof(program->'selected') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'journal allocator lacks actual source trigger' USING ERRCODE='42501';END IF;
 actual:=p_row||jsonb_build_object('created_at',transaction_timestamp());
 SELECT count(*)::integer,min(e.ordinal) INTO matches,matched_ordinal
 FROM pg_temp.kaname_authority_sequence_effects e
 WHERE e.nonce=(program->>'nonce')::uuid AND e.table_name='resource_journal' AND e.selected
  AND e.origin_digest=sha256(convert_to(p_origin::text,'UTF8')) AND e.row_digest=sha256(convert_to(actual::text,'UTF8'))
  AND e.origin=p_origin AND e.row_value=actual;
 IF matches<>1 OR NOT EXISTS(SELECT 1 FROM pg_temp.kaname_authority_sequence_effects e
  WHERE e.nonce=(program->>'nonce')::uuid AND e.ordinal=matched_ordinal AND e.registered) THEN
  RAISE EXCEPTION 'journal source origin was not registered by actual statement' USING ERRCODE='42501';END IF;
 RETURN kaname._authority_sequence_claim_v3('resource_journal',p_origin,actual);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Внутренний SOURCE-фрагмент общей dependency closure. Assembly допускается
-- только вместе со всеми producer compilers/finalizers; runtime ещё не проверен.
-- Maximum не является разрешением эффекта. Его строят только owner-private
-- compilers из защищённого графа; caller не получает EXECUTE этого primitive.
CREATE FUNCTION kaname._authority_sequence_excluded_v3(p_table oid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l
  WHERE l.pid=pg_backend_pid() AND l.locktype='relation' AND l.relation=p_table
  AND l.granted AND l.mode IN ('ShareLock','ShareRowExclusiveLock','ExclusiveLock','AccessExclusiveLock'));
$$;

CREATE FUNCTION kaname._authority_sequence_store_v3() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE header jsonb;result jsonb;
BEGIN
 header:=kaname._authority_sequence_header_v3();
 IF header IS NULL THEN RETURN NULL;END IF;
 -- Полный immutable compiler input нужен только холодным finalizer-вызовам.
 SELECT to_jsonb(s) INTO STRICT result FROM pg_temp.kaname_authority_sequence_program s WHERE s.singleton;
 RETURN result;
END $$;

CREATE FUNCTION kaname._authority_sequence_reserve_v3(p_family text,p_maximum jsonb,p_reads integer)
RETURNS integer LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;owner_oid oid;storage oid;grantee record;entry jsonb;item record;
 table_name text;table_id oid;sequence_id oid;column_name text;key_namespace integer;
 identifier bigint;identifiers bigint[];present boolean;ordinal integer:=0;used integer:=0;maximum jsonb:='[]'::jsonb;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR current_setting('transaction_isolation')<>'read committed'
 OR p_family IS NULL OR p_family NOT IN ('resource','binding','role','cluster','metadata','sa_state')
 OR jsonb_typeof(p_maximum) IS DISTINCT FROM 'array' OR jsonb_array_length(p_maximum)>100000
 OR p_reads IS NULL OR p_reads<0 OR p_reads>4096 THEN
  RAISE EXCEPTION 'invalid bounded sequence maximum' USING ERRCODE='42501';END IF;
 IF kaname._authority_sequence_store_v3() IS NOT NULL THEN
  RAISE EXCEPTION 'sequence maximum already reserved' USING ERRCODE='42501';END IF;
 IF 8+2*((jsonb_array_length(p_maximum)+255)/256)>p_reads THEN
  RAISE EXCEPTION 'sequence maximum read budget exceeded' USING ERRCODE='54000';END IF;
 SELECT oid INTO STRICT owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
 -- RX каждой actual таблицы предшествует любому её key, как direct INSERT.
 FOR table_name IN SELECT DISTINCT value->>'table' FROM jsonb_array_elements(p_maximum) ORDER BY 1 LOOP
  IF table_name NOT IN ('resource_journal','fga_outbox') OR table_name IS NULL THEN
   RAISE EXCEPTION 'sequence maximum table escaped closed family' USING ERRCODE='42501';END IF;
  table_id:=to_regclass('kaname.'||table_name);
  sequence_id:=CASE table_name WHEN 'resource_journal' THEN 'kaname.resource_journal_sequence_no_seq'::regclass
   ELSE 'kaname.fga_outbox_id_seq'::regclass END;
  IF NOT has_table_privilege((proof->>'invoker_oid')::oid,table_id,'INSERT')
  OR NOT has_sequence_privilege((proof->>'invoker_oid')::oid,sequence_id,'USAGE,UPDATE')
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid=table_id OR inhparent=table_id) THEN
   RAISE EXCEPTION 'sequence reservation lacks original INSERT privileges or exact relation' USING ERRCODE='42501';END IF;
  EXECUTE format('LOCK TABLE ONLY kaname.%I IN ROW EXCLUSIVE MODE',table_name);used:=used+2;
 END LOOP;
 FOR entry IN SELECT value FROM jsonb_array_elements(p_maximum) LOOP
  ordinal:=ordinal+1;table_name:=entry->>'table';
  IF jsonb_typeof(entry) IS DISTINCT FROM 'object'
  OR entry-'table'-'origin'-'ordinal'-'row'-'stamp'<>'{}'::jsonb
  OR jsonb_typeof(entry->'origin') IS DISTINCT FROM 'object'
  OR jsonb_typeof(entry->'row') IS DISTINCT FROM 'object'
  OR entry->>'ordinal' IS DISTINCT FROM ordinal::text
  OR coalesce(entry->>'stamp','') NOT IN ('transaction','decision')
  OR entry->'row' ? 'created_at' OR entry->'row' ? 'id' OR entry->'row' ? 'sequence_no' THEN
   RAISE EXCEPTION 'invalid exact sequence descriptor' USING ERRCODE='42501';END IF;
  sequence_id:=CASE table_name WHEN 'resource_journal' THEN 'kaname.resource_journal_sequence_no_seq'::regclass
   ELSE 'kaname.fga_outbox_id_seq'::regclass END;
  identifier:=nextval(sequence_id);
  IF identifier<=0 THEN RAISE EXCEPTION 'sequence identity exhausted' USING ERRCODE='P1034';END IF;
  maximum:=maximum||jsonb_build_array(entry||jsonb_build_object('reserved_id',identifier));
 END LOOP;
 -- Канонический порядок hash keys независимо от выбранной TTL-ветви.
 FOR item IN SELECT DISTINCT CASE value->>'table' WHEN 'resource_journal' THEN 1262569304 ELSE 1262569305 END ns,
  hashtext(value->>'reserved_id') h FROM jsonb_array_elements(maximum) ORDER BY ns,h LOOP
  PERFORM pg_advisory_xact_lock(item.ns,item.h);
 END LOOP;
 -- Страницы точных ключей, а не новый лимит 2046 эффектов из N singleton reads.
 -- Число descriptor остаётся ограничено отдельно; все candidate keys уже held.
 FOR table_name IN SELECT DISTINCT value->>'table' FROM jsonb_array_elements(maximum) ORDER BY 1 LOOP
  column_name:=CASE table_name WHEN 'resource_journal' THEN 'sequence_no' ELSE 'id' END;
  FOR identifiers IN
   SELECT array_agg(numbered.identifier ORDER BY numbered.identifier) FROM (
    SELECT (value->>'reserved_id')::bigint identifier,
     (row_number() OVER (ORDER BY (value->>'reserved_id')::bigint)-1)/256 page
    FROM jsonb_array_elements(maximum) WHERE value->>'table'=table_name
   ) numbered GROUP BY numbered.page ORDER BY numbered.page
  LOOP
   present:=false;
   EXECUTE format('SELECT EXISTS(SELECT 1 FROM (SELECT %I FROM ONLY kaname.%I WHERE %I=ANY($1) ORDER BY %I FOR UPDATE) locked)',
    column_name,table_name,column_name,column_name) INTO present USING identifiers;
   used:=used+1;
   IF present THEN RAISE EXCEPTION 'sequence reservation collided' USING ERRCODE='P1034';END IF;
  END LOOP;
 END LOOP;
 storage:=to_regclass('pg_temp.kaname_authority_sequence_program');
 IF storage IS NULL THEN
  CREATE TEMP TABLE pg_temp.kaname_authority_sequence_program(
   singleton boolean PRIMARY KEY CHECK(singleton),backend integer NOT NULL,transaction_id xid8 NOT NULL,
   invoker_oid oid NOT NULL,nonce uuid NOT NULL,family text NOT NULL,maximum jsonb NOT NULL,frozen jsonb NOT NULL DEFAULT '{}',staged_decision_at timestamptz NOT NULL,
   selected jsonb,unselected jsonb,decision_at timestamptz,frozen_mode text,
   effects_oid oid NOT NULL,maximum_count integer NOT NULL,selected_count integer) ON COMMIT DELETE ROWS;
  CREATE TEMP TABLE pg_temp.kaname_authority_sequence_effects(
   ordinal integer PRIMARY KEY CHECK(ordinal>0),nonce uuid NOT NULL,table_name text NOT NULL,
   reserved_id bigint NOT NULL CHECK(reserved_id>0),origin jsonb NOT NULL,row_value jsonb NOT NULL,
   origin_digest bytea NOT NULL,row_digest bytea NOT NULL,
   selected boolean NOT NULL DEFAULT false,registered boolean NOT NULL DEFAULT false,
   claimed boolean NOT NULL DEFAULT false,consumed boolean NOT NULL DEFAULT false,
   UNIQUE(nonce,table_name,reserved_id)) ON COMMIT DELETE ROWS;
  CREATE INDEX kaname_authority_sequence_effect_origin ON pg_temp.kaname_authority_sequence_effects
   (nonce,table_name,origin_digest,row_digest,ordinal);
  CREATE INDEX kaname_authority_sequence_effect_next ON pg_temp.kaname_authority_sequence_effects
   (nonce,table_name,selected,claimed,ordinal);
  REVOKE ALL ON pg_temp.kaname_authority_sequence_effects FROM PUBLIC;
  FOR grantee IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_class c
   CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE c.oid='pg_temp.kaname_authority_sequence_effects'::regclass AND a.grantee<>owner_oid LOOP
   EXECUTE format('REVOKE ALL ON pg_temp.kaname_authority_sequence_effects FROM %I',grantee.rolname);
  END LOOP;
  CREATE CONSTRAINT TRIGGER authority_sequence_program_completion_v3
   AFTER INSERT ON pg_temp.kaname_authority_sequence_program
   DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
   EXECUTE FUNCTION kaname.authority_sequence_program_completion_v3();
  REVOKE ALL ON pg_temp.kaname_authority_sequence_program FROM PUBLIC;
  FOR grantee IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_class c
   CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE c.oid='pg_temp.kaname_authority_sequence_program'::regclass AND a.grantee<>owner_oid LOOP
   EXECUTE format('REVOKE ALL ON pg_temp.kaname_authority_sequence_program FROM %I',grantee.rolname);
  END LOOP;
 END IF;
 PERFORM kaname._authority_sequence_shape_v3();
 INSERT INTO pg_temp.kaname_authority_sequence_program(singleton,backend,transaction_id,invoker_oid,nonce,family,maximum,staged_decision_at,effects_oid,maximum_count)
 VALUES(true,(proof->>'backend')::integer,(proof->>'transaction_id')::xid8,(proof->>'invoker_oid')::oid,
  (proof->>'nonce')::uuid,p_family,maximum,(proof->>'decision_at')::timestamptz,
  'pg_temp.kaname_authority_sequence_effects'::regclass,jsonb_array_length(maximum));
 INSERT INTO pg_temp.kaname_authority_sequence_effects(ordinal,nonce,table_name,reserved_id,origin,row_value,origin_digest,row_digest)
 SELECT (e.value->>'ordinal')::integer,(proof->>'nonce')::uuid,e.value->>'table',
  (e.value->>'reserved_id')::bigint,e.value->'origin',e.value->'row',
  sha256(convert_to((e.value->'origin')::text,'UTF8')),sha256(convert_to((e.value->'row')::text,'UTF8'))
 FROM jsonb_array_elements(maximum) e(value);
 RETURN used;
END $$;

-- Выбор делает family finalizer, а не caller. Здесь только проверка subset и
-- подстановка единственного уже прочитанного clock в заранее известную форму.
CREATE FUNCTION kaname._authority_sequence_select_v3(p_ordinals integer[],p_at timestamptz)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;maximum_value jsonb;maximum_count integer;ordinal_membership jsonb;
 distinct_ordinals integer;ordered_ordinals jsonb;chosen jsonb;discarded jsonb;
BEGIN
 program:=kaname._authority_sequence_store_v3();
 maximum_value:=program->'maximum';maximum_count:=jsonb_array_length(maximum_value);
 IF program IS NULL OR program->'selected'<>'null'::jsonb OR p_at IS NULL OR p_ordinals IS NULL
 OR cardinality(p_ordinals)>maximum_count
 OR EXISTS(SELECT 1 FROM unnest(p_ordinals) x(slot_ordinal)
  WHERE x.slot_ordinal IS NULL OR x.slot_ordinal<1 OR x.slot_ordinal>maximum_count) THEN
  RAISE EXCEPTION 'sequence final selection is not a closed ordered subset' USING ERRCODE='42501';END IF;
 -- Один immutable индекс ordinal вместо ANY для каждого элемента maximum.
 SELECT coalesce(jsonb_object_agg(x.slot_ordinal::text,true),'{}'::jsonb),
  count(DISTINCT x.slot_ordinal)::integer,
  coalesce(jsonb_agg(x.slot_ordinal ORDER BY x.slot_ordinal),'[]'::jsonb)
 INTO ordinal_membership,distinct_ordinals,ordered_ordinals
 FROM unnest(p_ordinals) x(slot_ordinal);
 IF cardinality(p_ordinals)<>distinct_ordinals OR to_jsonb(p_ordinals) IS DISTINCT FROM ordered_ordinals THEN
  RAISE EXCEPTION 'sequence final selection is not a closed ordered subset' USING ERRCODE='42501';END IF;
 -- Оба результата собираются агрегатами, без копирования растущего массива.
 -- Порядок maximum и прежние transaction/decision timestamps сохраняются.
 WITH entries AS MATERIALIZED (
  SELECT e.value,e.position,
   ordinal_membership ? ((e.value->>'ordinal')::integer)::text AS is_selected
  FROM jsonb_array_elements(maximum_value) WITH ORDINALITY e(value,position)
 )
 SELECT coalesce(jsonb_agg(e.value||jsonb_build_object('row',
   (e.value->'row')||jsonb_build_object('created_at',
    CASE e.value->>'stamp' WHEN 'transaction' THEN transaction_timestamp() ELSE p_at END))
   ORDER BY e.position) FILTER (WHERE e.is_selected),'[]'::jsonb),
  coalesce(jsonb_agg(e.value->'ordinal' ORDER BY e.position)
   FILTER (WHERE NOT coalesce(e.is_selected,false)),'[]'::jsonb)
 INTO chosen,discarded FROM entries e;
 PERFORM kaname._authority_sequence_publish_v3(chosen);
 UPDATE pg_temp.kaname_authority_sequence_program SET selected=chosen,unselected=discarded,decision_at=p_at,selected_count=jsonb_array_length(chosen);
END $$;

CREATE FUNCTION kaname._authority_sequence_claim_v3(p_table text,p_origin jsonb,p_row jsonb)
RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;matches integer;matched_ordinal integer;identifier bigint;key_namespace integer;changed integer;
BEGIN
 program:=kaname._authority_sequence_header_v3();
 IF program IS NULL OR jsonb_typeof(program->'selected') IS DISTINCT FROM 'array'
 OR p_table NOT IN ('resource_journal','fga_outbox') OR p_table IS NULL THEN
  RAISE EXCEPTION 'final sequence program missing' USING ERRCODE='42501';END IF;
 SELECT count(*)::integer,min(e.ordinal) INTO matches,matched_ordinal
 FROM pg_temp.kaname_authority_sequence_effects e
 WHERE e.nonce=(program->>'nonce')::uuid AND e.table_name=p_table AND e.selected AND NOT e.claimed
  AND e.origin_digest=sha256(convert_to(p_origin::text,'UTF8')) AND e.row_digest=sha256(convert_to(p_row::text,'UTF8'))
  AND e.origin=p_origin AND e.row_value=p_row;
 IF matches<>1 THEN RAISE EXCEPTION 'sequence origin or multiplicity differs from selected program' USING ERRCODE='42501';END IF;
 SELECT e.reserved_id INTO STRICT identifier FROM pg_temp.kaname_authority_sequence_effects e
  WHERE e.nonce=(program->>'nonce')::uuid AND e.ordinal=matched_ordinal;
 key_namespace:=CASE p_table WHEN 'resource_journal' THEN 1262569304 ELSE 1262569305 END;
 PERFORM kaname._authority_resource_preheld_key_v2(key_namespace,identifier::text,true);
 UPDATE pg_temp.kaname_authority_sequence_effects e SET claimed=true
  WHERE e.nonce=(program->>'nonce')::uuid AND e.ordinal=matched_ordinal AND e.selected AND NOT e.claimed;
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed<>1 THEN RAISE EXCEPTION 'sequence origin or multiplicity differs from selected program' USING ERRCODE='42501';END IF;
 RETURN identifier;
END $$;

CREATE FUNCTION kaname._authority_sequence_applied_v3(p_table text,p_identifier bigint,p_row jsonb)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;changed integer;
BEGIN
 program:=kaname._authority_sequence_header_v3();
 IF program IS NULL OR jsonb_typeof(program->'selected') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'sequence applied without selected program' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_authority_sequence_effects e SET consumed=true
 WHERE e.nonce=(program->>'nonce')::uuid AND e.table_name=p_table AND e.reserved_id=p_identifier
  AND e.selected AND e.claimed AND NOT e.consumed
  AND e.row_digest=sha256(convert_to(p_row::text,'UTF8')) AND e.row_value=p_row;
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed<>1 THEN RAISE EXCEPTION 'sequence applied ID replay or foreign row' USING ERRCODE='42501';END IF;
END $$;

CREATE FUNCTION kaname._authority_sequence_complete_v3() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;
BEGIN
 program:=kaname._authority_sequence_header_v3();
 IF program IS NULL THEN RETURN;END IF;
 IF program#>>'{frozen,mode}'='authorize' THEN
  RAISE EXCEPTION 'authorization-only transaction cannot commit' USING ERRCODE='42501';END IF;
 IF jsonb_typeof(program->'selected') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'sequence program never finalized' USING ERRCODE='42501';END IF;
 IF (SELECT count(*) FROM pg_temp.kaname_authority_sequence_effects)<>(program->>'maximum_count')::integer
 OR (SELECT count(*) FROM pg_temp.kaname_authority_sequence_effects e WHERE e.selected)<>(program->>'selected_count')::integer
 OR EXISTS(SELECT 1 FROM pg_temp.kaname_authority_sequence_effects e
  WHERE e.nonce<>(program->>'nonce')::uuid
   OR (e.selected AND (NOT e.claimed OR NOT e.consumed))
   OR (NOT e.selected AND (e.registered OR e.claimed OR e.consumed))) THEN
  RAISE EXCEPTION 'selected sequence program is incomplete' USING ERRCODE='42501';END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_resource_finalize_v2(p_intent jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(decision_at timestamptz,logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb; expected jsonb; actual jsonb; keys text[]; at_time timestamptz; count_rows integer;
 materialized jsonb;entry jsonb;field text;actual_keys text[];held_keys text[];
BEGIN
 IF p_rows IS NULL OR p_rows<0 OR p_rows>100000 OR p_reads IS NULL OR p_reads<1 OR p_reads>4096 THEN
  RAISE EXCEPTION 'resource final budget exceeded' USING ERRCODE='54000';
 END IF;
 manifest:=kaname._authority_resource_manifest_v2();
 IF manifest->>'state' IS DISTINCT FROM 'prepared' OR p_intent IS DISTINCT FROM manifest->'intent' THEN
  RAISE EXCEPTION 'resource final intent mismatch or repeated final clock' USING ERRCODE='42501';
 END IF;
 expected:=manifest->'native_epochs';
 IF jsonb_typeof(expected) IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'resource native epoch manifest missing' USING ERRCODE='42501';
 END IF;
 SELECT coalesce(array_agg(k),ARRAY[]::text[]) INTO keys FROM jsonb_object_keys(expected) k;
 count_rows:=cardinality(keys);
 IF count_rows>4096 OR count_rows>p_rows THEN
  RAISE EXCEPTION 'resource final epoch budget exceeded' USING ERRCODE='54000';
 END IF;
 -- Отсутствие exact epoch не превращается в нулевую revision. Prewait уже
 -- закрепил каждый ключ и его gap; здесь не INSERT и не FOR SHARE/UPDATE.
 SELECT coalesce(jsonb_object_agg(k,CASE WHEN e.key IS NULL THEN 'null'::jsonb
  ELSE jsonb_build_array(e.generation,e.revision) END),'{}'::jsonb)
 INTO actual FROM unnest(keys) k LEFT JOIN kaname.authority_policy_epoch e ON e.key=k;
 IF actual IS DISTINCT FROM expected THEN
  RAISE EXCEPTION 'resource native source changed' USING ERRCODE='P1034';
 END IF;
 at_time:=clock_timestamp();
 IF manifest->'intent'->>'kind'='object' THEN
  materialized:=kaname._authority_resource_object_materialize_v2(manifest->'object_certificate',
   manifest->'object_effects',manifest->'object_sources',manifest->'object_audit_reservations',
   (manifest->>'transaction_at')::timestamptz,at_time);
  -- Чистая финальная сборка не расширяет preclock maximum: обе TTL ветви
  -- заранее закрыли все logical/physical waits и возможные scope keys.
  FOR entry IN SELECT value FROM jsonb_array_elements(materialized->'writes') LOOP
   FOREACH field IN ARRAY ARRAY['epoch_write_keys','epoch_share_keys','source_guard_write_keys','source_guard_read_keys',
    'binding_epoch_write_scopes','binding_epoch_share_scopes','deferred_carrier_roles'] LOOP
    actual_keys:=kaname._authority_resource_key_array_v2(entry->field,field LIKE 'binding_epoch_%');
    held_keys:=kaname._authority_resource_key_array_v2(manifest->field,field LIKE 'binding_epoch_%');
    IF field IN ('epoch_share_keys','source_guard_read_keys','binding_epoch_share_scopes') THEN
     held_keys:=held_keys||kaname._authority_resource_key_array_v2(manifest->(CASE field
      WHEN 'epoch_share_keys' THEN 'epoch_write_keys' WHEN 'source_guard_read_keys' THEN 'source_guard_write_keys'
      ELSE 'binding_epoch_write_scopes' END),field LIKE 'binding_epoch_%');
    END IF;
    IF NOT actual_keys<@held_keys THEN
     RAISE EXCEPTION 'final object effect exceeds preclock physical maximum' USING ERRCODE='42501';END IF;
   END LOOP;
  END LOOP;
  PERFORM kaname._authority_resource_object_sequence_final_v3(materialized,at_time);
  UPDATE pg_temp.kaname_authority_resource_manifest SET writes=materialized->'writes',
   object_program=materialized->'program',object_physical=materialized->'physical',object_fold=materialized->'fold',
   object_outbox_write_ordinals=materialized->'object_outbox_write_ordinals',
   object_step_obligations=materialized->'step_obligations';
 ELSIF manifest->'intent'->>'kind'='crud' THEN
  PERFORM kaname._authority_crud_manifest_domain_v3(manifest);
  materialized:=kaname._authority_resource_crud_materialize_v3(manifest->'intent',
   manifest->'registration_certificate',manifest->'registration_sources',
   manifest->'registration_body',(manifest->>'transaction_at')::timestamptz,at_time);
  IF jsonb_typeof(materialized->'writes') IS DISTINCT FROM 'array'
  OR jsonb_typeof(materialized->'physical') IS DISTINCT FROM 'object'
  OR jsonb_typeof(materialized#>'{program,commands}') IS DISTINCT FROM 'array'
  OR jsonb_typeof(materialized->'step_obligations') IS DISTINCT FROM 'object' THEN
   RAISE EXCEPTION 'CRUD private materialization missing' USING ERRCODE='42501';END IF;
  FOR entry IN SELECT value FROM jsonb_array_elements(materialized->'writes') LOOP
   FOREACH field IN ARRAY ARRAY['epoch_write_keys','epoch_share_keys','source_guard_write_keys','source_guard_read_keys',
    'binding_epoch_write_scopes','binding_epoch_share_scopes','deferred_carrier_roles'] LOOP
    actual_keys:=kaname._authority_resource_key_array_v2(entry->field,field LIKE 'binding_epoch_%');
    held_keys:=kaname._authority_resource_key_array_v2(manifest->field,field LIKE 'binding_epoch_%');
    IF field IN ('epoch_share_keys','source_guard_read_keys','binding_epoch_share_scopes') THEN
     held_keys:=held_keys||kaname._authority_resource_key_array_v2(manifest->(CASE field
      WHEN 'epoch_share_keys' THEN 'epoch_write_keys' WHEN 'source_guard_read_keys' THEN 'source_guard_write_keys'
      ELSE 'binding_epoch_write_scopes' END),field LIKE 'binding_epoch_%');
    END IF;
    IF NOT actual_keys<@held_keys THEN
     RAISE EXCEPTION 'final CRUD effect exceeds preclock physical maximum' USING ERRCODE='42501';END IF;
   END LOOP;
  END LOOP;
  UPDATE pg_temp.kaname_authority_resource_manifest SET writes=materialized->'writes',registration_body=materialized,
   registration_program=materialized->'program',registration_physical=materialized->'physical',
   registration_step_obligations=materialized->'step_obligations',
   registration_outbox_write_ordinals=materialized->'registration_outbox_write_ordinals';
 ELSIF coalesce(manifest->'intent'->>'Action','') IN ('1','2','3','4','5') THEN
  IF manifest->'intent'->>'Action'='5' THEN
   -- A verified negative audit has no installation/native permission to grant.
   -- Its exact one-row body was derived and protected before the final clock.
   IF manifest#>'{registration_authority,refusal_only}' IS DISTINCT FROM 'true'::jsonb
   OR manifest#>'{registration_authority,accounts}' IS DISTINCT FROM '{}'::jsonb
   OR manifest#>'{registration_authority,native_epochs}' IS DISTINCT FROM '{}'::jsonb
   OR manifest#>'{registration_body,writes}' IS DISTINCT FROM '[]'::jsonb
   OR manifest#>>'{registration_certificate,action}' IS DISTINCT FROM '5'
   OR manifest#>>'{registration_body,program,commands,0,kind}' IS DISTINCT FROM 'refusal_audit'
   OR jsonb_array_length(manifest#>'{registration_body,program,commands}') IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'refusal final audit-only invariant invalid' USING ERRCODE='42501';END IF;
  ELSE
   PERFORM kaname._authority_resource_registration_authority_final_v2(manifest->'registration_authority',at_time);
  END IF;
  materialized:=manifest->'registration_body';
  IF manifest->'intent'->>'Action'='2' THEN
   materialized:=kaname._authority_resource_unregistration_materialize_v2(
    materialized->'source_index',materialized->'verified',materialized->'catalog',materialized->'direct',
    materialized->'maximum',materialized->'current',materialized->'reservations',
    (manifest->>'transaction_at')::timestamptz,at_time);
   PERFORM kaname._authority_resource_unregistration_operation_acl_v2(
    manifest#>'{registration_body,acl}',(manifest->>'invoker_oid')::oid,materialized->'cleanup_program');
   materialized:=materialized||jsonb_build_object('acl',manifest#>'{registration_body,acl}');
  END IF;
  IF jsonb_typeof(materialized->'writes') IS DISTINCT FROM 'array'
  OR jsonb_typeof(materialized->'physical') IS DISTINCT FROM 'object'
  OR jsonb_typeof(materialized->'program'->'commands') IS DISTINCT FROM 'array'
  OR jsonb_typeof(materialized->'step_obligations') IS DISTINCT FROM 'object' THEN
   RAISE EXCEPTION 'registration private materialization missing' USING ERRCODE='42501';END IF;
  FOR entry IN SELECT value FROM jsonb_array_elements(materialized->'writes') LOOP
   FOREACH field IN ARRAY ARRAY['epoch_write_keys','epoch_share_keys','source_guard_write_keys','source_guard_read_keys',
    'binding_epoch_write_scopes','binding_epoch_share_scopes','deferred_carrier_roles'] LOOP
    actual_keys:=kaname._authority_resource_key_array_v2(entry->field,field LIKE 'binding_epoch_%');
    held_keys:=kaname._authority_resource_key_array_v2(manifest->field,field LIKE 'binding_epoch_%');
    IF field IN ('epoch_share_keys','source_guard_read_keys','binding_epoch_share_scopes') THEN
     held_keys:=held_keys||kaname._authority_resource_key_array_v2(manifest->(CASE field
      WHEN 'epoch_share_keys' THEN 'epoch_write_keys' WHEN 'source_guard_read_keys' THEN 'source_guard_write_keys'
      ELSE 'binding_epoch_write_scopes' END),field LIKE 'binding_epoch_%');
    END IF;
    IF NOT actual_keys<@held_keys THEN
     RAISE EXCEPTION 'final registration effect exceeds preclock maximum' USING ERRCODE='42501';END IF;
   END LOOP;
  END LOOP;
  IF manifest->'intent'->>'Action'<>'5' THEN
   PERFORM kaname._authority_resource_registration_sequence_final_v3(materialized,at_time);
  END IF;
  UPDATE pg_temp.kaname_authority_resource_manifest SET writes=materialized->'writes',registration_body=materialized,
   registration_program=materialized->'program',registration_physical=materialized->'physical',
   registration_step_obligations=materialized->'step_obligations',
   registration_outbox_write_ordinals=materialized->'registration_outbox_write_ordinals';
 ELSE
  RAISE EXCEPTION 'resource final intent compiler unavailable' USING ERRCODE='42501';
 END IF;
 UPDATE pg_temp.kaname_authority_resource_manifest SET state='final',decision_at=at_time;
 UPDATE pg_temp.kaname_authority_attestation SET decision_at=at_time;
 UPDATE pg_temp.kaname_authority_consumer SET finalized=true;
 RETURN QUERY SELECT at_time,count_rows,1;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_resource_object_prepare_v2(p_envelope jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;source_index jsonb;catalog jsonb;certificate jsonb;effects jsonb;audit_plan jsonb;
 required jsonb;sources jsonb;maximum jsonb;predicates jsonb;policy jsonb;expected_accounts jsonb;
 epoch_result record;current_result record;catalog_result record;audit_result record;relations_result record;bundle_result record;
 held_advisory jsonb;compiled jsonb;entry record;global_required boolean;used_rows integer:=0;used_reads integer:=0;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource' OR proof->>'purpose' IS DISTINCT FROM 'participant'
 OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' IS DISTINCT FROM 'resource_pending'
 OR proof->>'consumer_finalized' IS DISTINCT FROM 'false' OR current_setting('transaction_isolation')<>'read committed'
 OR to_regclass('pg_temp.kaname_authority_resource_manifest') IS NOT NULL THEN
  RAISE EXCEPTION 'object prewait requires fresh pending RC admission' USING ERRCODE='42501';END IF;
 IF p_rows IS NULL OR p_rows<1 OR p_rows>100000 OR p_reads IS NULL OR p_reads<1 OR p_reads>4096
 OR jsonb_typeof(p_envelope) IS DISTINCT FROM 'object' OR octet_length(p_envelope::text)>67108864 THEN
  RAISE EXCEPTION 'object prewait budget exceeded' USING ERRCODE='54000';END IF;
 IF p_envelope->>'abi' IS DISTINCT FROM '2' OR p_envelope->'intent'->>'kind' IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_envelope->'object_effects') IS DISTINCT FROM 'object'
 OR p_envelope ? 'registration_effects'
 OR coalesce(nullif(p_envelope->'registration_accounts','null'::jsonb),'[]'::jsonb)<>'[]'::jsonb
 OR coalesce(nullif(p_envelope->'source_effects','null'::jsonb),'[]'::jsonb)<>'[]'::jsonb
 OR coalesce(nullif(p_envelope->'installation','null'::jsonb),'[]'::jsonb)<>'[]'::jsonb
 OR coalesce(nullif(p_envelope->'native_guards','null'::jsonb),'[]'::jsonb)<>'[]'::jsonb
 OR p_envelope->'native_epochs' IS DISTINCT FROM '{}'::jsonb
 OR coalesce(p_envelope->>'actor','')<>'' OR coalesce(p_envelope->>'service','')<>'' THEN
  RAISE EXCEPTION 'object prewait contains foreign operation authority' USING ERRCODE='42501';END IF;
 SELECT * INTO STRICT bundle_result FROM kaname._authority_resource_bundle_catalog_v2(p_rows,p_reads);
 catalog:=bundle_result.catalog;used_rows:=used_rows+bundle_result.logical_rows;used_reads:=used_reads+bundle_result.logical_reads;
 -- Декодирование RR строк не является новым DB чтением; их исходный read
 -- уже входит в shared attempt budget. Каждый used predicate перечитывается ниже.
 source_index:=kaname._authority_resource_capture_index_v2(p_envelope->'sources',100000);
 effects:=p_envelope->'object_effects';
 certificate:=kaname._authority_resource_object_certificate_v2(source_index,catalog,p_envelope->'intent',effects);
 audit_plan:=kaname._authority_resource_audit_plan_v2(source_index,effects->'bindings',effects->'audit_ids');
 required:=(certificate->'required')||(audit_plan->'required');
 sources:=kaname._authority_resource_object_physical_sources_v2(source_index,required);
 maximum:=kaname._authority_resource_object_maximum_v2(certificate,sources,audit_plan,effects);
 -- Исторический delete fold делает SELECT ... FOR UPDATE. Это требует
 -- UPDATE хотя бы одной колонки, даже если позднее DML только DELETE.
 -- Protocol-only source FOR SHARE не превращает все read ACL в write ACL.
 IF (maximum#>'{operations,relation_fact}') ? 'DELETE'
 AND NOT has_any_column_privilege((proof->>'invoker_oid')::oid,'kaname.relation_fact','UPDATE') THEN
  RAISE EXCEPTION 'legacy fact delete row lock requires UPDATE privilege' USING ERRCODE='42501';END IF;
 predicates:=kaname._authority_resource_predicate_maximum_v2(source_index,required);
 -- WRITE побеждает SHARE при совпадении. Нет позднего повышения режима.
 policy:=(predicates->'policy_epochs')||(maximum->'policy_epochs');
 maximum:=jsonb_set(maximum,'{policy_epochs}',policy);
 global_required:=(certificate->>'global')::boolean OR (predicates->>'global')::boolean;
 IF global_required IS NULL OR (proof->>'mode'='global') IS DISTINCT FROM global_required THEN
  RAISE EXCEPTION 'object scope classification changed before physical entry' USING ERRCODE='P1034';END IF;
 SELECT coalesce(jsonb_agg(k ORDER BY k COLLATE "C"),'[]'::jsonb) INTO expected_accounts
  FROM jsonb_object_keys(certificate->'accounts') k;
 IF NOT global_required AND (expected_accounts='[]'::jsonb OR proof->'accounts' IS DISTINCT FROM expected_accounts) THEN
  RAISE EXCEPTION 'object complete mutation accounts differ from admission' USING ERRCODE='P1034';END IF;
 IF (SELECT count(*) FROM jsonb_object_keys(policy))+(SELECT count(*) FROM jsonb_object_keys(maximum->'source_guards'))
  +(SELECT count(*) FROM jsonb_object_keys(maximum->'binding_epochs'))>4096 THEN
  RAISE EXCEPTION 'object complete lock key budget exceeded' USING ERRCODE='54000';END IF;
 SELECT * INTO STRICT epoch_result FROM kaname._authority_resource_epoch_wait_v2(maximum->'source_guards',policy,
  maximum->'binding_epochs',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+epoch_result.logical_rows;used_reads:=used_reads+epoch_result.logical_reads;
 SELECT * INTO STRICT catalog_result FROM kaname._authority_resource_catalog_wait_v2(p_envelope->'catalogs',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+catalog_result.logical_rows;used_reads:=used_reads+catalog_result.logical_reads;
 -- Каждый фактический output тип должен иметь current catalog capture;
 -- arbitrary дополнительная строка не заменяет отсутствующий required тип.
 FOR entry IN SELECT * FROM jsonb_each(certificate->'graphs') LOOP
  IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(catalog_result.catalog_rows) c
   WHERE c->>'dotted'=entry.value->>'object_type' AND c->>'object_type'=entry.value->>'model_type') THEN
   RAISE EXCEPTION 'object graph catalog capture omitted' USING ERRCODE='42501';END IF;
 END LOOP;
 SELECT * INTO STRICT current_result FROM kaname._authority_resource_required_reread_v2(source_index,required,
  sources->'write_keys',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+current_result.logical_rows;used_reads:=used_reads+current_result.logical_reads;
 IF current_result.predicate_protections IS DISTINCT FROM predicates->'protections' THEN
  RAISE EXCEPTION 'object current predicate maximum changed' USING ERRCODE='P1034';END IF;
 -- Пустой server-derived набор не требует чужих ACL или relation locks.
 -- Семантический certificate и полный current reread при этом обязательны.
 IF audit_plan->'ids'='{}'::jsonb THEN
  SELECT '[]'::jsonb AS lock_witness,0 AS logical_rows,0 AS logical_reads INTO audit_result;
 ELSE
  SELECT * INTO STRICT audit_result FROM kaname._authority_resource_audit_wait_v2(audit_plan->'ids',p_rows-used_rows,p_reads-used_reads);
 END IF;
 used_rows:=used_rows+audit_result.logical_rows;used_reads:=used_reads+audit_result.logical_reads;
 IF maximum->'operations'='{}'::jsonb THEN
  SELECT '[]'::jsonb AS lock_witness,0 AS logical_reads INTO relations_result;
 ELSE
  SELECT * INTO STRICT relations_result FROM kaname._authority_resource_physical_relations_wait_v2(maximum->'operations',p_reads-used_reads);
 END IF;
 used_reads:=used_reads+relations_result.logical_reads;
 IF used_rows>p_rows OR used_reads>p_reads THEN RAISE EXCEPTION 'object prewait aggregate budget exceeded' USING ERRCODE='54000';END IF;
 held_advisory:=(epoch_result.lock_witness->'held_advisory')||audit_result.lock_witness;
 compiled:=jsonb_build_object('intent',p_envelope->'intent','certificate',certificate,'effects',effects,'sources',sources,
  'audit_reservations',audit_plan->'reservations','maximum',maximum,'epoch_witness',epoch_result.lock_witness,
  'catalog_rows',catalog_result.catalog_rows,'held_relations',relations_result.lock_witness,'held_advisory',held_advisory);
 used_reads:=used_reads+kaname._authority_resource_object_sequence_prepare_v3(compiled,p_reads-used_reads);
 PERFORM kaname._authority_resource_object_store_v2(compiled);
 RETURN QUERY SELECT used_rows,used_reads;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Exact происхождение сохраняется через dedup и delete-tail; Go API прежний.
CREATE OR REPLACE FUNCTION kaname._authority_resource_object_program_v2(p_bindings jsonb,p_at timestamptz)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE item jsonb;command jsonb;tuple_value jsonb;tuples jsonb;branch jsonb;
 result jsonb:='[]'::jsonb;pending jsonb:='[]'::jsonb;seen jsonb:='{}'::jsonb;bindings jsonb:='{}'::jsonb;
 identifier text;kind text;tuple_key text;work integer:=0;branch_name text;branch_ordinal integer;
BEGIN
 IF p_at IS NULL OR jsonb_typeof(p_bindings) IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'invalid verified object program' USING ERRCODE='42501';END IF;
 IF jsonb_array_length(p_bindings)>4096 OR octet_length(p_bindings::text)>67108864 THEN
  RAISE EXCEPTION 'object program budget exceeded' USING ERRCODE='54000';END IF;
 -- Сортировка носителей совпадает с immutable proposal. Она не является
 -- полной выборкой БД и ограничена уже проверенным числом носителей.
 FOR item IN SELECT value FROM jsonb_array_elements(p_bindings) ORDER BY value->>'binding' COLLATE "C" LOOP
  identifier:=item->>'binding';
  IF coalesce(identifier,'')='' OR bindings ? identifier
  OR jsonb_typeof(item->'active') IS DISTINCT FROM 'boolean'
  OR jsonb_typeof(item->'live') IS DISTINCT FROM 'array'
  OR jsonb_typeof(item->'expired') IS DISTINCT FROM 'array' THEN
   RAISE EXCEPTION 'invalid verified carrier program' USING ERRCODE='42501';END IF;
  bindings:=bindings||jsonb_build_object(identifier,true);
  branch_name:=CASE WHEN (item->>'active')::boolean AND
   (item->>'expires_at' IS NULL OR (item->>'expires_at')::timestamptz>p_at)
   THEN 'live' ELSE 'expired' END;
  branch:=item->branch_name;branch_ordinal:=0;
  FOR command IN SELECT value FROM jsonb_array_elements(branch) LOOP
   branch_ordinal:=branch_ordinal+1;
   command:=command||jsonb_build_object('SequenceOrigin',jsonb_build_object('binding',identifier,'branch',branch_name,'ordinal',branch_ordinal));
   work:=work+1;kind:=command->>'Kind';
   IF kind IS NULL OR kind NOT IN ('members','record','forget','write','delete','member_delete','audit') THEN
    RAISE EXCEPTION 'unsupported verified object operation' USING ERRCODE='42501';END IF;
   IF kind='delete' THEN
    -- Все удаления остаются в хвосте; окончательное вычитание выполняется
    -- только после writes ВСЕХ выбранных по final TTL носителей.
    pending:=pending||jsonb_build_array(command);
   ELSIF kind='write' THEN
    IF jsonb_typeof(command->'Tuples') IS DISTINCT FROM 'array' THEN
     RAISE EXCEPTION 'invalid verified write tuple set' USING ERRCODE='42501';END IF;
    tuples:='[]'::jsonb;
    FOR tuple_value IN SELECT value FROM jsonb_array_elements(command->'Tuples') LOOP
     work:=work+1;
     IF work>100000 THEN RAISE EXCEPTION 'object program work exceeded' USING ERRCODE='54000';END IF;
     tuple_key:=tuple_value::text;
     IF NOT seen ? tuple_key THEN
      seen:=seen||jsonb_build_object(tuple_key,true);tuples:=tuples||jsonb_build_array(tuple_value);
     END IF;
    END LOOP;
    IF jsonb_array_length(tuples)>0 THEN result:=result||jsonb_build_array(jsonb_set(command,'{Tuples}',tuples));END IF;
   ELSE result:=result||jsonb_build_array(command);
   END IF;
   IF work>100000 THEN RAISE EXCEPTION 'object program work exceeded' USING ERRCODE='54000';END IF;
  END LOOP;
 END LOOP;
 FOR command IN SELECT value FROM jsonb_array_elements(pending) LOOP
  IF jsonb_typeof(command->'Tuples') IS DISTINCT FROM 'array' THEN
   RAISE EXCEPTION 'invalid verified delete tuple set' USING ERRCODE='42501';END IF;
  tuples:='[]'::jsonb;
  FOR tuple_value IN SELECT value FROM jsonb_array_elements(command->'Tuples') LOOP
   work:=work+1;
   IF work>100000 THEN RAISE EXCEPTION 'object program work exceeded' USING ERRCODE='54000';END IF;
   IF NOT seen ? tuple_value::text THEN tuples:=tuples||jsonb_build_array(tuple_value);END IF;
  END LOOP;
  IF jsonb_array_length(tuples)>0 THEN result:=result||jsonb_build_array(jsonb_set(command,'{Tuples}',tuples));END IF;
  IF work>100000 THEN RAISE EXCEPTION 'object program work exceeded' USING ERRCODE='54000';END IF;
 END LOOP;
 RETURN jsonb_build_object('commands',result,'work',work);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Object maximum: по одному slot на возможную (команда, объект, субъект)
-- группу каждой из двух уже проверенных TTL ветвей. Удаления резервируются
-- после всех выдач, как сам compiler; выброшенные IDs остаются sequence gaps.
CREATE FUNCTION kaname._authority_resource_object_sequence_prepare_v3(p_compiled jsonb,p_reads integer)
RETURNS integer LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE binding jsonb;command jsonb;branch_name text;branch_ordinal integer;phase integer;
 g record;origin jsonb;maximum jsonb:='[]';alternatives jsonb:='{}';slot integer:=0;work integer:=0;cost integer;
BEGIN
 IF p_compiled#>>'{intent,kind}' IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_compiled#>'{effects,bindings}') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'object sequence compiler lacks verified branches' USING ERRCODE='42501';END IF;
 FOR phase IN 0..1 LOOP
  FOR binding IN SELECT value FROM jsonb_array_elements(p_compiled#>'{effects,bindings}') ORDER BY value->>'binding' COLLATE "C" LOOP
   FOREACH branch_name IN ARRAY ARRAY['live','expired'] LOOP
    branch_ordinal:=0;
    FOR command IN SELECT value FROM jsonb_array_elements(binding->branch_name) LOOP
     branch_ordinal:=branch_ordinal+1;work:=work+1;
     IF work>200000 THEN RAISE EXCEPTION 'object sequence maximum work exceeded' USING ERRCODE='54000';END IF;
     IF command->>'Kind' IS DISTINCT FROM (CASE phase WHEN 0 THEN 'write' ELSE 'delete' END) THEN CONTINUE;END IF;
     FOR g IN SELECT (t->>'Object') COLLATE "C" object_id,(t->>'User') COLLATE "C" subject,
      jsonb_agg(DISTINCT (t->>'Relation') COLLATE "C" ORDER BY (t->>'Relation') COLLATE "C") relations
      FROM jsonb_array_elements(command->'Tuples') t
      GROUP BY (t->>'Object') COLLATE "C",(t->>'User') COLLATE "C" ORDER BY object_id,subject LOOP
      slot:=slot+1;work:=work+jsonb_array_length(g.relations);
      IF work>200000 OR slot>100000 THEN RAISE EXCEPTION 'object sequence maximum exceeded' USING ERRCODE='54000';END IF;
      origin:=jsonb_build_object('family','resource.object','binding',binding->>'binding','branch',branch_name,
       'ordinal',branch_ordinal,'event_type','fga.tuple.'||(command->>'Kind'),'object',g.object_id,'user',g.subject);
      IF alternatives ? origin::text THEN RAISE EXCEPTION 'object sequence origin repeated' USING ERRCODE='42501';END IF;
      alternatives:=alternatives||jsonb_build_object(origin::text,jsonb_build_object('slot',slot,'relations',g.relations));
      maximum:=maximum||jsonb_build_array(jsonb_build_object('table','fga_outbox','origin',origin,'ordinal',slot,
       'row','{}'::jsonb,'stamp',CASE phase WHEN 0 THEN 'transaction' ELSE 'decision' END));
     END LOOP;
    END LOOP;
   END LOOP;
  END LOOP;
 END LOOP;
 cost:=kaname._authority_sequence_reserve_v3('resource',maximum,p_reads);
 PERFORM kaname._authority_sequence_freeze_v3(jsonb_build_object('kind','object','alternatives',alternatives));
 RETURN cost;
END $$;

CREATE FUNCTION kaname._authority_resource_object_sequence_final_v3(p_materialized jsonb,p_at timestamptz)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;outbox jsonb;command jsonb;source jsonb;origin jsonb;option_value jsonb;
 chosen jsonb:='[]';row_value jsonb;relations jsonb;slot integer;last_slot integer:=0;
BEGIN
 program:=kaname._authority_sequence_store_v3();
 IF program->>'family' IS DISTINCT FROM 'resource' OR program#>>'{frozen,kind}' IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_materialized#>'{physical,outboxes}') IS DISTINCT FROM 'array'
 OR jsonb_typeof(p_materialized#>'{program,commands}') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'object final sequence program missing' USING ERRCODE='42501';END IF;
 FOR outbox IN SELECT value FROM jsonb_array_elements(p_materialized#>'{physical,outboxes}') LOOP
  command:=p_materialized#>ARRAY['program','commands',((outbox->>'command')::integer-1)::text];
  source:=command->'SequenceOrigin';row_value:=outbox->'row';
  IF jsonb_typeof(source) IS DISTINCT FROM 'object' OR jsonb_typeof(row_value) IS DISTINCT FROM 'object' THEN
   RAISE EXCEPTION 'object final sequence origin missing' USING ERRCODE='42501';END IF;
  origin:=source||jsonb_build_object('family','resource.object','event_type',row_value->>'event_type',
   'object',row_value#>>'{payload,object}','user',row_value#>>'{payload,user}');
  option_value:=program#>ARRAY['frozen','alternatives',origin::text];slot:=(option_value->>'slot')::integer;
  relations:=coalesce(row_value#>'{payload,relations}',jsonb_build_array(row_value#>'{payload,relation}'));
  IF slot IS NULL OR slot<=last_slot OR jsonb_typeof(relations) IS DISTINCT FROM 'array'
  OR jsonb_array_length(relations)=0 OR NOT (option_value->'relations') @> relations
  OR row_value-ARRAY['event_type','payload','created_at']<>'{}'::jsonb
  OR row_value->'payload'-ARRAY['user','object','relation','relations']<>'{}'::jsonb THEN
   RAISE EXCEPTION 'object final sequence escaped frozen origin or order' USING ERRCODE='42501';END IF;
  chosen:=chosen||jsonb_build_array(jsonb_build_object('ordinal',slot,
   'origin',origin||jsonb_build_object('command',outbox->'command'),'row',row_value-'created_at'));
  last_slot:=slot;
 END LOOP;
 PERFORM kaname._authority_sequence_bind_v3(chosen,p_at);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_resource_physical_relations_capture_v2(p_operations jsonb,p_reads integer,p_defer_acl boolean)
RETURNS TABLE(lock_witness jsonb,logical_reads integer,acl_capabilities jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 proof jsonb; invoker oid; role_name text; entry record; operation jsonb; relation_row record;
 relations jsonb:='[]'::jsonb; locks jsonb:='[]'::jsonb; item jsonb;capabilities jsonb:='{}';table_acl jsonb;allowed boolean;
 table_count integer; operation_count integer:=0; used_reads integer:=0; reserved_reads integer;
 relation_oid oid; outbox_oid oid; sequence_oid oid; sequence_name text; id_attnum smallint;
 needs_sequence boolean; ownership_ok boolean; default_ok boolean;
BEGIN
 IF p_defer_acl IS NULL THEN RAISE EXCEPTION 'resource ACL capture mode missing' USING ERRCODE='42501';END IF;
 IF p_reads IS NULL OR p_reads<0 OR p_reads>4096 THEN
  RAISE EXCEPTION 'invalid resource relation read budget' USING ERRCODE='54000';
 END IF;
 IF jsonb_typeof(p_operations) IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'resource relation operations must be an object' USING ERRCODE='42501';
 END IF;
 -- Лимит размера проверяется до разворачивания JSON; audit имеет отдельный слот.
 IF octet_length(p_operations::text)>16384 THEN
  RAISE EXCEPTION 'resource relation operations exceeded' USING ERRCODE='54000';
 END IF;
 SELECT count(*) INTO table_count FROM jsonb_object_keys(p_operations);
 IF table_count=0 OR table_count-(CASE WHEN p_operations ? 'audit_outbox' THEN 1 ELSE 0 END)>32 THEN
  RAISE EXCEPTION 'invalid resource relation width' USING ERRCODE='42501';
 END IF;
 FOR entry IN SELECT key,value FROM jsonb_each(p_operations) LOOP
  IF entry.key NOT IN (
   'roles','access_bindings','access_binding_subjects','access_binding_target_members','access_binding_emitted_tuples',
   'role_rule_selectors','role_selector_verbs_pending','role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule',
   'resource_mirror','resource_parent_edge','resource_registration_scope','resource_registration_pointer',
   'resource_registration_retirement','producer_source_receipt','public_read_publication','relation_fact','fga_outbox',
   'audit_outbox') OR jsonb_typeof(entry.value) IS DISTINCT FROM 'array' THEN
   RAISE EXCEPTION 'unsupported resource relation or operation array' USING ERRCODE='42501';
  END IF;
  IF jsonb_array_length(entry.value) NOT BETWEEN 1 AND 3 THEN
   RAISE EXCEPTION 'invalid resource operation count' USING ERRCODE='42501';
  END IF;
  FOR operation IN SELECT value FROM jsonb_array_elements(entry.value) LOOP
   IF jsonb_typeof(operation) IS DISTINCT FROM 'string' OR operation #>> '{}' NOT IN ('INSERT','UPDATE','DELETE') THEN
    RAISE EXCEPTION 'unsupported resource operation' USING ERRCODE='42501';
   END IF;
  END LOOP;
  IF (SELECT count(DISTINCT value) FROM jsonb_array_elements(entry.value))<>jsonb_array_length(entry.value) THEN
   RAISE EXCEPTION 'duplicate resource operation' USING ERRCODE='42501';
  END IF;
  operation_count:=operation_count+jsonb_array_length(entry.value);
 END LOOP;
 needs_sequence:=coalesce((p_operations->'fga_outbox') ? 'INSERT',false);
 -- Конечная верхняя граница включает admission, каталоги, ACL, acquisitions
 -- и повторные точечные проверки. Возвращается фактически списанное число.
 reserved_reads:=3+6*table_count+operation_count+CASE WHEN needs_sequence THEN 12 ELSE 0 END
  +CASE WHEN p_defer_acl AND p_operations ? 'relation_fact' THEN 1 ELSE 0 END;
 IF reserved_reads>p_reads THEN
  RAISE EXCEPTION 'resource relation read budget exceeded' USING ERRCODE='54000';
 END IF;
 used_reads:=used_reads+1;
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
 OR proof->>'purpose' IS DISTINCT FROM 'participant'
 OR coalesce(proof->>'consumer_profile','') NOT IN ('resource_pending','resource_source_pending')
 OR proof->>'consumer_abi' IS DISTINCT FROM '2'
 OR proof->>'consumer_finalized' IS DISTINCT FROM 'false'
 OR current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'resource relation wait requires pending RC ABI2 admission' USING ERRCODE='42501';
 END IF;
 role_name:=current_setting('role',true);
 IF role_name IS NULL OR role_name='none' THEN role_name:=session_user;END IF;
 used_reads:=used_reads+1;
 SELECT oid INTO invoker FROM pg_catalog.pg_roles WHERE rolname=role_name;
 IF invoker IS NULL OR proof->>'invoker_oid' IS DISTINCT FROM invoker::text THEN
  RAISE EXCEPTION 'resource relation invoker mismatch' USING ERRCODE='42501';
 END IF;
 used_reads:=used_reads+1;
 IF NOT has_schema_privilege(invoker,'kaname','USAGE') THEN
  RAISE EXCEPTION 'resource relation requires caller schema usage' USING ERRCODE='42501';
 END IF;
 -- Вся проверка обычного invoker завершается до первого LOCK/nextval.
 -- SELECT нужен predicates UPDATE/DELETE. INSERT-only без RETURNING
 -- не получает дополнительного ACL требования; current-image readers и
 -- audit reservation проверяет creator отдельно до своих чтений. Closure
 -- включает UPDATE для syntactic ON CONFLICT DO UPDATE даже без UPDATE image.
 FOR entry IN SELECT key,value FROM jsonb_each(p_operations) ORDER BY key COLLATE "C" LOOP
  used_reads:=used_reads+1;
  SELECT c.oid,c.relkind,c.relpersistence INTO relation_row
   FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='kaname' AND c.relname=entry.key;
  IF NOT FOUND OR relation_row.relkind<>'r' OR relation_row.relpersistence<>'p' THEN
   RAISE EXCEPTION 'resource target must be a permanent ordinary table' USING ERRCODE='42501';
  END IF;
  relation_oid:=relation_row.oid;
  used_reads:=used_reads+1;
  IF EXISTS(SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid=relation_oid OR inhparent=relation_oid) THEN
   RAISE EXCEPTION 'resource inherited target requires a separate physical closure' USING ERRCODE='42501';
  END IF;
  used_reads:=used_reads+1;
  table_acl:='{}';
  IF entry.value ? 'UPDATE' OR entry.value ? 'DELETE' THEN
   allowed:=has_table_privilege(invoker,relation_oid,'SELECT');
   table_acl:=table_acl||jsonb_build_object('SELECT',allowed);
   IF NOT allowed AND NOT p_defer_acl THEN
    RAISE EXCEPTION 'resource relation requires caller SELECT' USING ERRCODE='42501';END IF;
  END IF;
  FOR operation IN SELECT value FROM jsonb_array_elements(entry.value) LOOP
   used_reads:=used_reads+1;allowed:=has_table_privilege(invoker,relation_oid,operation #>> '{}');
   table_acl:=table_acl||jsonb_build_object(operation #>> '{}',allowed);
   IF NOT allowed AND NOT p_defer_acl THEN
    RAISE EXCEPTION 'resource relation requires caller % on %',operation #>> '{}',entry.key USING ERRCODE='42501';
   END IF;
  END LOOP;
  capabilities:=capabilities||jsonb_build_object(entry.key,table_acl);
  IF p_defer_acl AND entry.key='relation_fact' THEN
   used_reads:=used_reads+1;
   capabilities:=capabilities||jsonb_build_object('$fact_row_lock_update',has_any_column_privilege(invoker,relation_oid,'UPDATE'));
  END IF;
  relations:=relations||jsonb_build_array(jsonb_build_object('oid',relation_oid,'name',entry.key,'kind','table'));
  IF entry.key='fga_outbox' THEN outbox_oid:=relation_oid;END IF;
 END LOOP;
 IF needs_sequence THEN
  used_reads:=used_reads+1;
  sequence_name:=pg_get_serial_sequence('kaname.fga_outbox','id');
  IF sequence_name IS NULL THEN
   RAISE EXCEPTION 'resource outbox owned sequence missing' USING ERRCODE='42501';
  END IF;
  used_reads:=used_reads+1;
  SELECT c.oid INTO sequence_oid FROM pg_catalog.pg_class c
   WHERE c.oid=to_regclass(sequence_name) AND c.relkind='S' AND c.relpersistence='p';
  used_reads:=used_reads+1;
  SELECT a.attnum INTO id_attnum FROM pg_catalog.pg_attribute a
   WHERE a.attrelid=outbox_oid AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped;
  IF sequence_oid IS NULL OR id_attnum IS NULL THEN
   RAISE EXCEPTION 'resource outbox sequence identity invalid' USING ERRCODE='42501';
  END IF;
  used_reads:=used_reads+1;
  SELECT count(*)=1 AND coalesce(bool_and(d.refclassid='pg_catalog.pg_class'::regclass
   AND d.refobjid=outbox_oid AND d.refobjsubid=id_attnum AND d.deptype='a'),false)
   INTO ownership_ok FROM pg_catalog.pg_depend d
   WHERE d.classid='pg_catalog.pg_class'::regclass AND d.objid=sequence_oid AND d.objsubid=0 AND d.deptype IN ('a','i');
  used_reads:=used_reads+1;
  SELECT coalesce(bool_and(pg_get_expr(d.adbin,d.adrelid)='kaname.authority_fga_outbox_id_v3()'),false)
   INTO default_ok FROM pg_catalog.pg_attrdef d WHERE d.adrelid=outbox_oid AND d.adnum=id_attnum;
  IF NOT ownership_ok OR NOT default_ok THEN
   RAISE EXCEPTION 'resource outbox sequence ownership or default mismatch' USING ERRCODE='42501';
  END IF;
  used_reads:=used_reads+1;
  allowed:=has_sequence_privilege(invoker,sequence_oid,'USAGE,UPDATE');
  capabilities:=capabilities||jsonb_build_object('$fga_nextval',allowed);
  IF NOT allowed AND NOT p_defer_acl THEN
   RAISE EXCEPTION 'resource outbox requires caller sequence privilege' USING ERRCODE='42501';
  END IF;
  -- Exact nextval выполняет последующий family reservation после RX всех таблиц.
  -- Этот relation pass сохраняет sequence ownership/ACL, но не выбрасывает ID.
 END IF;
 -- Единый порядок actual OID для таблиц; sequence/key — в exact reservation ниже.
 FOR item IN SELECT value FROM jsonb_array_elements(relations) ORDER BY (value->>'oid')::oid LOOP
  relation_oid:=(item->>'oid')::oid;
  used_reads:=used_reads+1;
  IF item->>'kind'='sequence' THEN
   PERFORM pg_catalog.nextval(relation_oid::regclass);
  ELSE
   EXECUTE format('LOCK TABLE ONLY kaname.%I IN ROW EXCLUSIVE MODE',item->>'name');
   used_reads:=used_reads+1;
   IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE c.oid=relation_oid AND n.nspname='kaname' AND c.relname=item->>'name'
    AND c.relkind='r' AND c.relpersistence='p'
    AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid)) THEN
    RAISE EXCEPTION 'resource target changed during relation acquisition' USING ERRCODE='P1034';
   END IF;
  END IF;
  -- Witness возникает только после acquisition и точечной проверки удержания.
  used_reads:=used_reads+1;
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_backend_pid()
   AND l.locktype='relation' AND l.relation=relation_oid AND l.mode='RowExclusiveLock' AND l.granted) THEN
   RAISE EXCEPTION 'resource RowExclusive acquisition missing' USING ERRCODE='42501';
  END IF;
  locks:=locks||jsonb_build_array(jsonb_build_object('oid',relation_oid,'mode','RowExclusiveLock'));
 END LOOP;
 IF needs_sequence THEN
  -- DDL между catalog lookup и acquisition не становится новой authority.
  used_reads:=used_reads+1;
  IF pg_get_serial_sequence('kaname.fga_outbox','id')::regclass::oid IS DISTINCT FROM sequence_oid THEN
   RAISE EXCEPTION 'resource outbox sequence changed during acquisition' USING ERRCODE='P1034';
  END IF;
  used_reads:=used_reads+1;
  SELECT count(*)=1 AND coalesce(bool_and(d.refclassid='pg_catalog.pg_class'::regclass
   AND d.refobjid=outbox_oid AND d.refobjsubid=id_attnum AND d.deptype='a'),false)
   INTO ownership_ok FROM pg_catalog.pg_depend d
   WHERE d.classid='pg_catalog.pg_class'::regclass AND d.objid=sequence_oid AND d.objsubid=0 AND d.deptype IN ('a','i');
  used_reads:=used_reads+1;
  SELECT coalesce(bool_and(pg_get_expr(d.adbin,d.adrelid)='kaname.authority_fga_outbox_id_v3()'),false)
   INTO default_ok FROM pg_catalog.pg_attrdef d WHERE d.adrelid=outbox_oid AND d.adnum=id_attnum;
  IF NOT ownership_ok OR NOT default_ok THEN
   RAISE EXCEPTION 'resource outbox sequence binding changed during acquisition' USING ERRCODE='P1034';
  END IF;
 END IF;
 IF used_reads>p_reads OR used_reads>4096 THEN
  RAISE EXCEPTION 'resource relation read budget exceeded' USING ERRCODE='54000';
 END IF;
 RETURN QUERY SELECT locks,used_reads,jsonb_build_object('invoker_oid',invoker,'operations',capabilities);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Direct Register/Publish/Unpublish и cleanup имеют закрытые physical images.
-- У cleanup final clock меняет timestamps/holder fold, но не source identity
-- journal emitter и не перечень отправляемых tuple payload. Эти формы остаются
-- frozen; финал проверяет точную multiplicity и не пополняет резерв.
CREATE FUNCTION kaname._authority_resource_registration_sequence_prepare_v3(p_body jsonb,p_action integer,p_reads integer)
RETURNS integer LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE outbox jsonb;image_value jsonb;origin jsonb;row_value jsonb;source_row jsonb;kind text;
 maximum jsonb:='[]';frozen_fga jsonb:='[]';frozen_journal jsonb:='[]';slot integer:=0;n integer:=0;cost integer;
BEGIN
 IF p_action NOT IN (1,2,3,4,5) OR p_action IS NULL
 OR jsonb_typeof(p_body#>'{physical,outboxes}') IS DISTINCT FROM 'array'
 OR jsonb_typeof(p_body#>'{physical,images}') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'registration sequence maximum lacks physical program' USING ERRCODE='42501';END IF;
 FOR outbox IN SELECT value FROM jsonb_array_elements(p_body#>'{physical,outboxes}') LOOP
  slot:=slot+1;n:=n+1;row_value:=outbox->'row';
  origin:=jsonb_build_object('family','resource.registration','command',outbox->'command','ordinal',n);
  maximum:=maximum||jsonb_build_array(jsonb_build_object('table','fga_outbox','ordinal',slot,'origin',origin,
   'row','{}'::jsonb,'stamp',CASE p_action WHEN 2 THEN 'decision' ELSE 'transaction' END));
  frozen_fga:=frozen_fga||jsonb_build_array(jsonb_build_object('slot',slot,'origin',origin,'row',row_value-'created_at'));
 END LOOP;
 n:=0;
 FOR image_value IN SELECT value FROM jsonb_array_elements(p_body#>'{physical,images}') LOOP
  IF image_value->>'table' NOT IN ('roles','access_bindings') THEN CONTINUE;END IF;
  IF image_value->>'operation'<>'UPDATE' OR image_value->'required'<>'true'::jsonb THEN
   RAISE EXCEPTION 'registration journal source operation escaped closed UPDATE family' USING ERRCODE='42501';END IF;
  IF image_value->'old'=image_value->'new' THEN CONTINUE;END IF;
  slot:=slot+1;n:=n+1;source_row:=image_value->'new';
  kind:=CASE image_value->>'table' WHEN 'roles' THEN 'iam_role' ELSE 'iam_access_binding' END;
  origin:=jsonb_build_object('table',image_value->>'table','operation','UPDATE','when','AFTER',
   'id',source_row->>'id','ordinal',n,'command',image_value->'command');
  row_value:=jsonb_build_object('resource_kind',kind,'resource_id',source_row->>'id',
   'project_id',kaname.resource_journal_project(kind,source_row),'scope',kaname.resource_journal_scope(kind,source_row),
   'event_type','UPDATED','payload',jsonb_build_object('id',source_row->>'id'));
  maximum:=maximum||jsonb_build_array(jsonb_build_object('table','resource_journal','ordinal',slot,'origin',origin,
   'row','{}'::jsonb,'stamp','transaction'));
  frozen_journal:=frozen_journal||jsonb_build_array(jsonb_build_object('slot',slot,'origin',origin,'row',row_value));
 END LOOP;
 cost:=kaname._authority_sequence_reserve_v3('resource',maximum,p_reads);
 PERFORM kaname._authority_sequence_freeze_v3(jsonb_build_object('kind','registration','action',p_action,
  'fga',frozen_fga,'journal',frozen_journal));
 RETURN cost;
END $$;

CREATE FUNCTION kaname._authority_resource_registration_sequence_final_v3(p_body jsonb,p_at timestamptz)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;outbox jsonb;image_value jsonb;expected jsonb;origin jsonb;source_row jsonb;
 chosen jsonb:='[]';n integer:=0;
BEGIN
 program:=kaname._authority_sequence_store_v3();
 IF program->>'family' IS DISTINCT FROM 'resource' OR program#>>'{frozen,kind}' IS DISTINCT FROM 'registration' THEN
  RAISE EXCEPTION 'registration sequence final lacks frozen maximum' USING ERRCODE='42501';END IF;
 FOR outbox IN SELECT value FROM jsonb_array_elements(p_body#>'{physical,outboxes}') LOOP
  expected:=program#>ARRAY['frozen','fga',n::text];n:=n+1;
  IF expected IS NULL OR expected->'row' IS DISTINCT FROM outbox->'row'-'created_at'
  OR expected#>'{origin,command}' IS DISTINCT FROM outbox->'command' THEN
   RAISE EXCEPTION 'registration FGA origin/row/multiplicity changed after maximum' USING ERRCODE='42501';END IF;
  chosen:=chosen||jsonb_build_array(jsonb_build_object('ordinal',expected->'slot','origin',expected->'origin','row',expected->'row'));
 END LOOP;
 IF n<>jsonb_array_length(program#>'{frozen,fga}') THEN
  RAISE EXCEPTION 'registration FGA maximum was not selected exactly' USING ERRCODE='42501';END IF;
 n:=0;
 FOR image_value IN SELECT value FROM jsonb_array_elements(p_body#>'{physical,images}') LOOP
  IF image_value->>'table' NOT IN ('roles','access_bindings') THEN CONTINUE;END IF;
  IF image_value->>'operation'<>'UPDATE' OR image_value->'required'<>'true'::jsonb THEN
   RAISE EXCEPTION 'registration final journal source operation changed' USING ERRCODE='42501';END IF;
  IF image_value->'old'=image_value->'new' THEN CONTINUE;END IF;
  expected:=program#>ARRAY['frozen','journal',n::text];n:=n+1;source_row:=image_value->'new';
  origin:=jsonb_build_object('table',image_value->>'table','operation','UPDATE','when','AFTER',
   'id',source_row->>'id','ordinal',n,'command',image_value->'command');
  IF expected IS NULL OR expected->'origin' IS DISTINCT FROM origin THEN
   RAISE EXCEPTION 'registration final journal origin/count escaped maximum' USING ERRCODE='42501';END IF;
  origin:=jsonb_build_object('table',image_value->>'table','operation','UPDATE','when','AFTER',
   'old',image_value->'old','new',image_value->'new');
  chosen:=chosen||jsonb_build_array(jsonb_build_object('ordinal',expected->'slot','origin',origin,'row',expected->'row'));
 END LOOP;
 IF n<>jsonb_array_length(program#>'{frozen,journal}') THEN
  RAISE EXCEPTION 'registration final journal missing source effect' USING ERRCODE='42501';END IF;
 PERFORM kaname._authority_sequence_bind_v3(chosen,p_at);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_resource_registration_direct_prepare_v2(p_envelope jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;source_index jsonb;certificate jsonb;sources jsonb;program jsonb;maximum jsonb;predicates jsonb;policy jsonb;
 reservations jsonb;materialized jsonb;compiled jsonb;held_relations jsonb;held_advisory jsonb;required jsonb;operations jsonb;
 expected_accounts jsonb;key_value text;entry record;global_required boolean;requires_update boolean;
 bundle_result record;catalog_result record;epoch_result record;current_result record;authority_result record;
 binding_result record;audit_result record;reconcile_result record;relation_result record;
 used_rows integer:=0;used_reads integer:=0;action_value integer;audit_id text;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource' OR proof->>'purpose' IS DISTINCT FROM 'participant'
 OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' IS DISTINCT FROM 'resource_pending'
 OR proof->>'consumer_finalized' IS DISTINCT FROM 'false' OR current_setting('transaction_isolation')<>'read committed'
 OR to_regclass('pg_temp.kaname_authority_resource_manifest') IS NOT NULL THEN
  RAISE EXCEPTION 'registration direct compiler requires fresh pending RC admission' USING ERRCODE='42501';END IF;
 IF p_rows IS NULL OR p_rows<1 OR p_rows>100000 OR p_reads IS NULL OR p_reads<1 OR p_reads>4096
 OR jsonb_typeof(p_envelope) IS DISTINCT FROM 'object' OR octet_length(p_envelope::text)>67108864 THEN
  RAISE EXCEPTION 'registration direct compiler input exceeded' USING ERRCODE='54000';END IF;
 IF coalesce(p_envelope->'intent'->>'Action','') NOT IN ('1','3','4')
 OR coalesce(nullif(p_envelope->'source_effects','null'::jsonb),'[]'::jsonb)<>'[]'::jsonb THEN
  RAISE EXCEPTION 'registration direct compiler cannot admit source mutation' USING ERRCODE='42501';END IF;
 action_value:=(p_envelope->'intent'->>'Action')::integer;
 SELECT * INTO STRICT bundle_result FROM kaname._authority_resource_bundle_catalog_v2(p_rows,p_reads);
 used_rows:=used_rows+bundle_result.logical_rows;used_reads:=used_reads+bundle_result.logical_reads;
 SELECT * INTO STRICT catalog_result FROM kaname._authority_resource_catalog_wait_v2(p_envelope->'catalogs',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+catalog_result.logical_rows;used_reads:=used_reads+catalog_result.logical_reads;
 source_index:=kaname._authority_resource_capture_index_v2(p_envelope->'sources',100000);
 certificate:=kaname._authority_resource_registration_intent_certificate_v2(source_index,bundle_result.catalog,catalog_result.catalog_rows,p_envelope);
 sources:=kaname._authority_resource_registration_direct_sources_v2(source_index,certificate);
 IF action_value=1 THEN
  program:=kaname._authority_resource_registration_direct_program_v2(certificate,sources->'before',transaction_timestamp());
 ELSE
  program:=kaname._authority_resource_publication_direct_program_v2(certificate,sources->'before',transaction_timestamp());
 END IF;
 maximum:=kaname._authority_resource_registration_maximum_v2(source_index,certificate,sources,program,p_envelope->'native_guards');
 required:=maximum->'required';predicates:=kaname._authority_resource_predicate_maximum_v2(source_index,required);
 policy:=(predicates->'policy_epochs')||(maximum->'policy_epochs');
 maximum:=jsonb_set(maximum,'{policy_epochs}',policy);
 global_required:=(maximum->>'global')::boolean OR (predicates->>'global')::boolean;
 IF global_required IS NULL OR (proof->>'mode'='global') IS DISTINCT FROM global_required THEN
  RAISE EXCEPTION 'registration complete mutation classification changed' USING ERRCODE='P1034';END IF;
 SELECT coalesce(jsonb_agg(k ORDER BY k COLLATE "C"),'[]'::jsonb) INTO expected_accounts FROM jsonb_object_keys(maximum->'accounts') k;
 IF NOT global_required AND (expected_accounts='[]'::jsonb OR proof->'accounts' IS DISTINCT FROM expected_accounts) THEN
  RAISE EXCEPTION 'registration complete mutation accounts differ from admission' USING ERRCODE='P1034';END IF;
 -- Publication delete с хотя бы одним pointer выполнял SELECT FOR UPDATE,
 -- даже если actual fact отсутствует. Без pointer историческая ветвь не читает.
 SELECT coalesce(bool_or(value->'requires_update_acl'='true'::jsonb),false) INTO requires_update
  FROM jsonb_array_elements(program->'steps');
 IF requires_update AND NOT has_any_column_privilege((proof->>'invoker_oid')::oid,'kaname.relation_fact','UPDATE') THEN
  RAISE EXCEPTION 'publication fact row lock requires UPDATE privilege' USING ERRCODE='42501';END IF;
 SELECT * INTO STRICT epoch_result FROM kaname._authority_resource_epoch_wait_v2(maximum->'source_guards',policy,
  maximum->'binding_epochs',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+epoch_result.logical_rows;used_reads:=used_reads+epoch_result.logical_reads;
 IF action_value=1 THEN
  SELECT * INTO STRICT binding_result FROM kaname._authority_resource_registration_binding_wait_v2(certificate,program,p_reads-used_reads);
 ELSE SELECT '[]'::jsonb held_relations,'[]'::jsonb held_advisory,0 logical_reads INTO binding_result;END IF;
 used_reads:=used_reads+binding_result.logical_reads;
 SELECT * INTO STRICT current_result FROM kaname._authority_resource_required_reread_v2(source_index,required,
  sources->'write_keys',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+current_result.logical_rows;used_reads:=used_reads+current_result.logical_reads;
 IF current_result.predicate_protections IS DISTINCT FROM predicates->'protections' THEN
  RAISE EXCEPTION 'registration current predicate maximum changed' USING ERRCODE='P1034';END IF;
 SELECT * INTO STRICT authority_result FROM kaname._authority_resource_registration_authority_wait_v2(
  p_envelope,certificate,bundle_result.model_source,epoch_result.lock_witness,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+authority_result.logical_rows;used_reads:=used_reads+authority_result.logical_reads;
 audit_id:=NULL;
 IF program->'audit_required'='true'::jsonb THEN
  audit_id:=certificate->>'audit_id';
  IF audit_id IS NULL OR audit_id !~ '^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$' THEN
   RAISE EXCEPTION 'registration audit ID reservation missing' USING ERRCODE='42501';END IF;
  SELECT * INTO STRICT audit_result FROM kaname._authority_resource_audit_wait_v2(jsonb_build_object(audit_id,true),p_rows-used_rows,p_reads-used_reads);
 ELSE SELECT '[]'::jsonb lock_witness,0 logical_rows,0 logical_reads INTO audit_result;END IF;
 used_rows:=used_rows+audit_result.logical_rows;used_reads:=used_reads+audit_result.logical_reads;
 IF program->'reconcile_required'='true'::jsonb THEN
  SELECT * INTO STRICT reconcile_result FROM kaname._authority_resource_reconcile_wait_v2(1,p_reads-used_reads);
 ELSE SELECT '[]'::jsonb reserved_ids,'[]'::jsonb held_relations,'[]'::jsonb held_advisory,0 logical_reads INTO reconcile_result;END IF;
 used_reads:=used_reads+reconcile_result.logical_reads;
 operations:=(maximum->'operations')-'object_project_binding';
 IF operations='{}'::jsonb THEN SELECT '[]'::jsonb lock_witness,0 logical_reads INTO relation_result;
 ELSE
  SELECT * INTO STRICT relation_result FROM kaname._authority_resource_physical_relations_wait_v2(operations,p_reads-used_reads);
 END IF;
 used_reads:=used_reads+relation_result.logical_reads;
 reservations:=jsonb_build_object('audit_id',audit_id,'reconcile_ids',reconcile_result.reserved_ids);
 materialized:=kaname._authority_resource_registration_materialize_v2(certificate,maximum,sources,program,reservations,transaction_timestamp());
 held_relations:=relation_result.lock_witness||binding_result.held_relations||reconcile_result.held_relations;
 held_advisory:=(epoch_result.lock_witness->'held_advisory')||binding_result.held_advisory||audit_result.lock_witness||reconcile_result.held_advisory;
 IF used_rows>p_rows OR used_reads>p_reads THEN RAISE EXCEPTION 'registration aggregate prewait budget exceeded' USING ERRCODE='54000';END IF;
 compiled:=jsonb_build_object('intent',p_envelope->'intent','certificate',certificate,'sources',sources,'program',program,
  'authority',authority_result.authority,'body',materialized,'maximum',maximum,'epoch_witness',epoch_result.lock_witness,
  'catalog_rows',catalog_result.catalog_rows,'held_relations',held_relations,'held_advisory',held_advisory);
 used_reads:=used_reads+kaname._authority_resource_registration_sequence_prepare_v3(materialized,action_value,p_reads-used_reads);
 PERFORM kaname._authority_resource_registration_store_v2(compiled);
 RETURN QUERY SELECT used_rows,used_reads;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_resource_unregistration_prepare_v2(p_envelope jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;source_index jsonb;verified jsonb;certificate jsonb;direct jsonb;plan jsonb;maximum jsonb;predicates jsonb;policy jsonb;
 current_state jsonb;reservations jsonb;body jsonb;compiled jsonb;required jsonb;operations jsonb;expected_accounts jsonb;expected_sources jsonb;
 audit_ids jsonb:='{}';audit_id text;key_value text;global_required boolean;source_required boolean;
 bundle_result record;catalog_result record;epoch_result record;current_result record;authority_result record;
 audit_result record;reconcile_result record;subject_result record;relation_result record;
 sequence_body jsonb;used_rows integer:=0;used_reads integer:=0;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource' OR proof->>'purpose' IS DISTINCT FROM 'participant'
 OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' NOT IN ('resource_pending','resource_source_pending')
 OR proof->>'consumer_finalized' IS DISTINCT FROM 'false' OR current_setting('transaction_isolation')<>'read committed'
 OR to_regclass('pg_temp.kaname_authority_resource_manifest') IS NOT NULL THEN
  RAISE EXCEPTION 'cleanup compiler requires fresh pending RC admission' USING ERRCODE='42501';END IF;
 IF p_rows IS NULL OR p_rows<1 OR p_rows>100000 OR p_reads IS NULL OR p_reads<1 OR p_reads>4096
 OR jsonb_typeof(p_envelope) IS DISTINCT FROM 'object' OR octet_length(p_envelope::text)>67108864
 OR p_envelope#>>'{intent,Action}' IS DISTINCT FROM '2' THEN
  RAISE EXCEPTION 'cleanup compiler input invalid' USING ERRCODE='42501';END IF;
 SELECT * INTO STRICT bundle_result FROM kaname._authority_resource_bundle_catalog_v2(p_rows,p_reads);
 used_rows:=used_rows+bundle_result.logical_rows;used_reads:=used_reads+bundle_result.logical_reads;
 SELECT * INTO STRICT catalog_result FROM kaname._authority_resource_catalog_wait_v2(p_envelope->'catalogs',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+catalog_result.logical_rows;used_reads:=used_reads+catalog_result.logical_reads;
 source_index:=kaname._authority_resource_capture_index_v2(p_envelope->'sources',100000);
 verified:=kaname._authority_resource_unregistration_certificate_v2(source_index,bundle_result.catalog,catalog_result.catalog_rows,p_envelope->'catalogs',p_envelope);
 certificate:=verified->'certificate';
 direct:=kaname._authority_resource_unregistration_direct_program_v2(source_index,verified,transaction_timestamp());
 plan:=kaname._authority_resource_unregistration_operation_maximum_v2(verified,direct);
 source_required:=plan->'source_effects'='true'::jsonb;
 IF (proof->>'consumer_profile'='resource_source_pending') IS DISTINCT FROM source_required THEN
  RAISE EXCEPTION 'cleanup SOURCE classification changed' USING ERRCODE='P1034';END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('kind',effect.kind,'id',effect.id) ORDER BY effect.kind COLLATE "C",effect.id COLLATE "C"),'[]'::jsonb)
 INTO expected_sources FROM (
  SELECT 'binding'::text kind,k id FROM jsonb_object_keys(verified->'changed_bindings') k
  UNION ALL SELECT 'role',k FROM jsonb_object_keys(verified->'changed_roles') k) effect;
 IF coalesce(nullif(p_envelope->'source_effects','null'::jsonb),'[]'::jsonb) IS DISTINCT FROM expected_sources THEN
  RAISE EXCEPTION 'cleanup SOURCE write census differs' USING ERRCODE='P1034';END IF;
 maximum:=kaname._authority_resource_unregistration_maximum_v2(source_index,verified,direct,catalog_result.catalog_rows,plan,p_envelope->'native_guards');
 required:=maximum->'required';predicates:=kaname._authority_resource_predicate_maximum_v2(source_index,required);
 policy:=(predicates->'policy_epochs')||(maximum->'policy_epochs');maximum:=jsonb_set(maximum,'{policy_epochs}',policy);
 global_required:=(maximum->>'global')::boolean OR (predicates->>'global')::boolean;
 IF global_required IS NULL OR (proof->>'mode'='global') IS DISTINCT FROM global_required THEN
  RAISE EXCEPTION 'cleanup complete mutation classification changed' USING ERRCODE='P1034';END IF;
 SELECT coalesce(jsonb_agg(q.key ORDER BY q.key COLLATE "C"),'[]'::jsonb) INTO expected_accounts FROM jsonb_object_keys(maximum->'accounts') q(key);
 IF NOT global_required AND (expected_accounts='[]'::jsonb OR proof->'accounts' IS DISTINCT FROM expected_accounts) THEN
  RAISE EXCEPTION 'cleanup complete mutation accounts changed' USING ERRCODE='P1034';END IF;
 SELECT * INTO STRICT epoch_result FROM kaname._authority_resource_epoch_wait_v2(maximum->'source_guards',policy,
  maximum->'binding_epochs',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+epoch_result.logical_rows;used_reads:=used_reads+epoch_result.logical_reads;
 SELECT * INTO STRICT current_result FROM kaname._authority_resource_required_reread_v2(source_index,required,
  maximum->'write_sources',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+current_result.logical_rows;used_reads:=used_reads+current_result.logical_reads;
 IF current_result.predicate_protections IS DISTINCT FROM predicates->'protections' THEN
  RAISE EXCEPTION 'cleanup current predicate maximum changed' USING ERRCODE='P1034';END IF;
 SELECT * INTO STRICT authority_result FROM kaname._authority_resource_registration_authority_wait_v2(
  p_envelope,certificate,bundle_result.model_source,epoch_result.lock_witness,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+authority_result.logical_rows;used_reads:=used_reads+authority_result.logical_reads;
 FOR audit_id IN SELECT jsonb_array_elements_text(verified->'withdrawal_audit_ids') LOOP
  audit_ids:=audit_ids||jsonb_build_object(audit_id,true);
 END LOOP;
 audit_id:=NULL;
 IF plan->'audit_possible'='true'::jsonb THEN
  audit_id:=certificate->>'audit_id';
  IF coalesce(audit_id,'') !~ '^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$' OR audit_ids ? audit_id THEN
   RAISE EXCEPTION 'cleanup root audit reservation invalid' USING ERRCODE='42501';END IF;
  audit_ids:=audit_ids||jsonb_build_object(audit_id,true);
 END IF;
 IF audit_ids<>'{}'::jsonb THEN
  SELECT * INTO STRICT audit_result FROM kaname._authority_resource_audit_capture_wait_v2(audit_ids,p_rows-used_rows,p_reads-used_reads,true);
 ELSE SELECT '[]'::jsonb lock_witness,0 logical_rows,0 logical_reads INTO audit_result;END IF;
 used_rows:=used_rows+audit_result.logical_rows;used_reads:=used_reads+audit_result.logical_reads;
 SELECT * INTO STRICT reconcile_result FROM kaname._authority_resource_reconcile_wait_v2((plan->>'reconcile_count')::integer,p_reads-used_reads);
 used_reads:=used_reads+reconcile_result.logical_reads;
 IF (verified->>'withdrawal_subject_count')::integer>0 THEN
  SELECT * INTO STRICT subject_result FROM kaname._authority_resource_subject_change_wait_v2((verified->>'withdrawal_subject_count')::integer,p_reads-used_reads);
 ELSE SELECT '[]'::jsonb reserved_ids,'[]'::jsonb held_relations,'[]'::jsonb held_advisory,0 logical_reads INTO subject_result;END IF;
 used_reads:=used_reads+subject_result.logical_reads;
 operations:=(maximum->'operations')-ARRAY['resource_reconcile_outbox','subject_change_outbox'];
 SELECT * INTO STRICT relation_result FROM kaname._authority_resource_physical_relations_capture_v2(operations,p_reads-used_reads,true);
 used_reads:=used_reads+relation_result.logical_reads;
 reservations:=jsonb_build_object('audit_id',audit_id,'audit_ids',verified->'withdrawal_audit_ids',
  'subject_ids',subject_result.reserved_ids,'reconcile_ids',reconcile_result.reserved_ids);
 current_state:=kaname._authority_resource_unregistration_current_v2(source_index,maximum,direct);
 body:=jsonb_build_object('source_index',source_index,'verified',verified,'catalog',bundle_result.catalog,'direct',direct,
  'maximum',maximum,'current',current_state,'reservations',reservations,'acl',relation_result.acl_capabilities);
 IF used_rows>p_rows OR used_reads>p_reads THEN RAISE EXCEPTION 'cleanup aggregate prewait exceeded' USING ERRCODE='54000';END IF;
 compiled:=jsonb_build_object('intent',p_envelope->'intent','certificate',certificate,'sources',jsonb_build_object('required',required),
  'program',plan,'authority',authority_result.authority,'body',body,'maximum',maximum,'epoch_witness',epoch_result.lock_witness,
  'catalog_rows',catalog_result.catalog_rows,
  'held_relations',relation_result.lock_witness||reconcile_result.held_relations||subject_result.held_relations,
  'held_advisory',(epoch_result.lock_witness->'held_advisory')||audit_result.lock_witness||reconcile_result.held_advisory||subject_result.held_advisory);
 -- Только server-verified frozen inputs; предварительные часы — placeholder
 -- для формы. Authority/fold decision остаётся у единственного finalizer.
 sequence_body:=kaname._authority_resource_unregistration_materialize_v2(source_index,verified,bundle_result.catalog,direct,
  maximum,current_state,reservations,transaction_timestamp(),transaction_timestamp());
 used_reads:=used_reads+kaname._authority_resource_registration_sequence_prepare_v3(sequence_body,2,p_reads-used_reads);
 PERFORM kaname._authority_resource_registration_store_v2(compiled);
 RETURN QUERY SELECT used_rows,used_reads;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_role_stage_epoch_lock(p_accounts text[],p_expected jsonb) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; actual jsonb; at_time timestamptz; sequence_id regclass;
BEGIN
 PERFORM kaname._authority_sequence_expect_v3('role');
 IF p_expected IS NULL OR pg_catalog.jsonb_typeof(p_expected)<>'object' THEN RAISE EXCEPTION 'binding epoch snapshot is absent' USING ERRCODE='40001'; END IF;
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL THEN RAISE EXCEPTION 'role stage requires signed entry' USING ERRCODE='42501'; END IF;
 IF proof->>'purpose' IS DISTINCT FROM 'decision' OR proof->>'kind' IS DISTINCT FROM 'role' THEN RAISE EXCEPTION 'role stage requires role decision' USING ERRCODE='42501'; END IF;
 IF proof->>'mode' IS DISTINCT FROM 'accounts' AND proof->>'mode' IS DISTINCT FROM 'global' THEN RAISE EXCEPTION 'invalid role stage coordinator mode' USING ERRCODE='42501'; END IF;
 IF p_accounts IS NULL THEN
  IF proof->>'mode' IS DISTINCT FROM 'global' THEN RAISE EXCEPTION 'binding global epoch requires global entry' USING ERRCODE='42501'; END IF;
 ELSE
  IF pg_catalog.cardinality(p_accounts)=0 OR EXISTS(SELECT 1 FROM pg_catalog.unnest(p_accounts) a WHERE a IS NULL OR a='') THEN RAISE EXCEPTION 'invalid binding epoch scope'; END IF;
  IF proof->>'mode'='accounts' AND (pg_catalog.jsonb_typeof(proof->'accounts') IS DISTINCT FROM 'array' OR NOT (proof->'accounts') @> pg_catalog.to_jsonb(p_accounts)) THEN RAISE EXCEPTION 'epoch accounts exceed role decision scope' USING ERRCODE='42501'; END IF;
 END IF;
 -- SELECT FOR UPDATE держит только ROW SHARE на таблице. SHARE blocker
 -- пережил бы row prelock и задержал DML уже после решения. Закрытый union
 -- actual Create/Update footprints берётся в одном порядке ДО final clock.
 -- Включены триггеры resource journal, policy/binding epochs и deferred
 -- carrier flush, а также ledger/outbox/fold; DML authority этим не выдаётся.
 LOCK TABLE kaname.access_binding_emitted_tuples,
   kaname.access_bindings,
   kaname.audit_outbox,
   kaname.authority_binding_epoch,
   kaname.authority_policy_carrier_pending,
   kaname.authority_policy_epoch,
   kaname.fga_outbox,
   kaname.relation_fact,
   kaname.resource_journal,
   kaname.resource_reconcile_outbox,
   kaname.role_bind_role_rule,
   kaname.role_create_binding_rule,
   kaname.role_rule_ref,
   kaname.role_rule_selectors,
   kaname.role_selector_verbs_pending,
   kaname.role_verb,
   kaname.roles IN ROW EXCLUSIVE MODE;
 -- У таблицы и её serial/identity sequence разные relation locks. nextval
 -- получает RowExclusiveLock sequence до конца TX и переносит ожидание
 -- ALTER SEQUENCE до final clock. Только закрытый actual union; никакого
 -- caller SQL, business DML или выдачи runtime прямых metadata privileges.
 -- Один номер на sequence на попытку допустимо пропускается (как rollback).
 -- Повторный epoch recheck не расходует номер: удерживаемый lock уже достаточен.
 FOREACH sequence_id IN ARRAY ARRAY[
   'kaname.resource_reconcile_outbox_id_seq'::regclass
 ] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l
    WHERE l.pid=pg_catalog.pg_backend_pid() AND l.locktype='relation'
      AND l.relation=sequence_id AND l.mode='RowExclusiveLock' AND l.granted) THEN
   PERFORM pg_catalog.nextval(sequence_id);
  END IF;
 END LOOP;
 IF p_accounts IS NULL THEN
  PERFORM scope FROM kaname.authority_binding_epoch WHERE scope='' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'binding epochs are uninitialized' USING ERRCODE='40001'; END IF;
 ELSE
  PERFORM scope FROM kaname.authority_binding_epoch WHERE scope='' FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'binding epochs are uninitialized' USING ERRCODE='40001'; END IF;
  PERFORM scope FROM kaname.authority_binding_epoch WHERE scope=ANY(p_accounts) ORDER BY scope FOR SHARE;
  IF (SELECT count(*) FROM kaname.authority_binding_epoch WHERE scope=ANY(p_accounts))<>(SELECT count(DISTINCT a) FROM pg_catalog.unnest(p_accounts) a) THEN RAISE EXCEPTION 'binding epoch disappeared' USING ERRCODE='40001'; END IF;
 END IF;
 actual:=kaname.authority_binding_epoch_read(p_accounts);
 IF actual IS DISTINCT FROM p_expected THEN RAISE EXCEPTION 'binding stage changed' USING ERRCODE='40001'; END IF;
 at_time:=pg_catalog.clock_timestamp();
 UPDATE pg_temp.kaname_authority_attestation SET decision_at=at_time;
 RETURN at_time;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Role program сохраняет фактическую retier-последовательность и отдельную
-- TTL-проекцию promotion. Истёкшие кандидаты резервируются, но не эмитятся.
CREATE FUNCTION kaname.authority_role_sequence_prepare_v3(p_input jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;old_role jsonb;new_role jsonb;proposed jsonb;mask jsonb;field_name text;version text;
 maximum jsonb:='[]';expiry jsonb:='{}';origin jsonb;row_value jsonb;carrier jsonb;new_carrier jsonb;
 root_stamp timestamptz:=transaction_timestamp();ordinal integer:=0;cost integer;item record;
 old_tuples jsonb;new_tuples jsonb;subjects jsonb;subject jsonb;tier text;user_ref text;relation_set jsonb;payload jsonb;
 retier boolean;creation boolean;promote boolean;side_name text;event_type text;
 scanned integer:=1;reads integer:=1;carriers integer:=0;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind'<>'role' OR proof->>'purpose'<>'decision'
 OR jsonb_typeof(p_input) IS DISTINCT FROM 'object'
 OR p_input-ARRAY['create','rules','retier','role','mask','version']<>'{}' THEN
  RAISE EXCEPTION 'role sequence input is not a closed request' USING ERRCODE='42501';END IF;
 IF p_rows IS NULL OR p_reads IS NULL OR p_rows NOT BETWEEN 1 AND 100000 OR p_reads NOT BETWEEN 1 AND 4096 THEN
  RAISE EXCEPTION 'role sequence budget is absent' USING ERRCODE='54000';END IF;
 creation:=(p_input->>'create')::boolean;promote:=(p_input->>'rules')::boolean;retier:=(p_input->>'retier')::boolean;
 IF creation IS NULL OR promote IS NULL OR retier IS NULL OR (retier AND (creation OR NOT promote)) THEN
  RAISE EXCEPTION 'invalid role mutation branch' USING ERRCODE='42501';END IF;
 proposed:=p_input->'role';mask:=p_input->'mask';
 IF jsonb_typeof(proposed) IS DISTINCT FROM 'object' OR coalesce(proposed->>'id','')=''
 OR proposed-ARRAY['id','account_id','project_id','name','description','rules','permissions','labels']<>'{}'
 OR jsonb_typeof(mask) IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'role row fields are not closed' USING ERRCODE='42501';END IF;
 IF creation THEN
  new_role:=to_jsonb(jsonb_populate_record(NULL::kaname.roles,proposed||jsonb_build_object(
   'account_id',nullif(proposed->>'account_id',''),'project_id',nullif(proposed->>'project_id',''),
   'cluster_id',NULL,'is_system',false,'owner_module',NULL,'owner_module_live',true,'live',true,
   'retired_at',NULL,'retired_reason',NULL,'retired_by',NULL,'created_at',root_stamp,'updated_at',root_stamp)));
 ELSE
  SELECT to_jsonb(r),r.xmin::text INTO STRICT old_role,version FROM kaname.roles r WHERE r.id=proposed->>'id' FOR UPDATE;
  -- OCC refusal остаётся у actual UpdateCAS с прежним FailedPrecondition.
  new_role:=old_role;
  IF jsonb_array_length(mask)=0 THEN mask:='["name","description","rules","permissions","labels"]';END IF;
  IF mask ? 'rules' AND NOT mask ? 'permissions' THEN mask:=mask||'"permissions"'::jsonb;END IF;
  FOR field_name IN SELECT value FROM jsonb_array_elements_text(mask) LOOP
   IF field_name NOT IN ('name','description','rules','permissions','labels') THEN
    RAISE EXCEPTION 'invalid role update mask' USING ERRCODE='42501';END IF;
   new_role:=new_role||jsonb_build_object(field_name,proposed->field_name);
  END LOOP;
  root_stamp:=greatest(root_stamp,(old_role->>'created_at')::timestamptz);
  IF jsonb_array_length(mask)>0 THEN new_role:=new_role||jsonb_build_object('updated_at',root_stamp);END IF;
 END IF;
 IF old_role IS DISTINCT FROM new_role THEN
  ordinal:=ordinal+1;
  origin:=jsonb_build_object('table','roles','operation',CASE WHEN creation THEN 'INSERT' ELSE 'UPDATE' END,
   'when','AFTER','old',old_role,'new',new_role);
  row_value:=jsonb_build_object('resource_kind','iam_role','resource_id',new_role->>'id',
   'project_id',kaname.resource_journal_project('iam_role',new_role),'scope',kaname.resource_journal_scope('iam_role',new_role),
   'event_type',CASE WHEN creation THEN 'CREATED' ELSE 'UPDATED' END,'payload',jsonb_build_object('id',new_role->>'id'));
  maximum:=maximum||jsonb_build_array(jsonb_build_object('table','resource_journal','ordinal',ordinal,'origin',origin,'row',row_value,'stamp','transaction'));
 END IF;
 IF creation AND new_role->>'account_id' IS NOT NULL THEN
  ordinal:=ordinal+1;
  row_value:=jsonb_build_object('event_type','fga.tuple.write','payload',jsonb_build_object(
   'user','account:'||(new_role->>'account_id'),'relation','account','object','iam_role:'||(new_role->>'id')));
  maximum:=maximum||jsonb_build_array(jsonb_build_object('table','fga_outbox','ordinal',ordinal,
   'origin',jsonb_build_object('family','role.create','role',new_role->>'id'),'row',row_value,'stamp','transaction'));
 END IF;
 IF NOT creation AND promote THEN
  FOR carrier IN SELECT to_jsonb(b) FROM kaname.access_bindings b WHERE b.role_id=new_role->>'id' ORDER BY b.id COLLATE "C" LIMIT 100001 LOOP
   carriers:=carriers+1;scanned:=scanned+1;
   IF carriers>p_rows OR scanned>p_rows OR jsonb_array_length(maximum)>100000 THEN RAISE EXCEPTION 'role sequence population bound' USING ERRCODE='54000';END IF;
   IF retier AND carrier->>'status'<>'REVOKED' THEN
    SELECT coalesce(jsonb_agg(jsonb_build_object('user',t.fga_user,'relation',t.relation,'object',t.object)
     ORDER BY t.object COLLATE "C",t.fga_user COLLATE "C",t.relation COLLATE "C"),'[]') INTO old_tuples
    FROM (SELECT * FROM kaname.access_binding_emitted_tuples e WHERE e.binding_id=carrier->>'id' AND e.source='binding' LIMIT p_rows-scanned+1) t;
    SELECT coalesce(jsonb_agg(jsonb_build_object('type',s.subject_type,'id',s.subject_id) ORDER BY s.ordinal,s.subject_type,s.subject_id),'[]') INTO subjects
    FROM (SELECT * FROM kaname.access_binding_subjects e WHERE e.binding_id=carrier->>'id' LIMIT 33) s;
    reads:=reads+2;scanned:=scanned+jsonb_array_length(old_tuples)+jsonb_array_length(subjects);
    IF reads>p_reads OR scanned>p_rows THEN RAISE EXCEPTION 'role sequence source budget' USING ERRCODE='54000';END IF;
    IF jsonb_array_length(subjects)=0 THEN subjects:=jsonb_build_array(jsonb_build_object('type',carrier->>'subject_type','id',carrier->>'subject_id'));END IF;
    IF jsonb_array_length(subjects)>32 OR jsonb_array_length(old_tuples)>100000 THEN
     RAISE EXCEPTION 'role binding program exceeds source bound' USING ERRCODE='54000';END IF;
    new_tuples:=jsonb_build_array(jsonb_build_object('user',(carrier->>'resource_type')||':'||(carrier->>'resource_id'),
     'relation',carrier->>'resource_type','object','iam_access_binding:'||(carrier->>'id')));
    tier:=kaname._authority_binding_scope_tier_v3(carrier->>'resource_type',new_role->'rules',new_role->'permissions');
    IF tier IS NOT NULL THEN
     FOR subject IN SELECT value FROM jsonb_array_elements(subjects) LOOP
      user_ref:=(subject->>'type')||':'||(subject->>'id')||CASE WHEN subject->>'type'='group' THEN '#member' ELSE '' END;
      new_tuples:=new_tuples||jsonb_build_array(jsonb_build_object('user',user_ref,'relation',tier,
       'object',(carrier->>'resource_type')||':'||(carrier->>'resource_id')));
     END LOOP;
    END IF;
    -- Сопоставление со spool не признаёт его программой: обе стороны заново
    -- выведены из protected business rows и точного domain request.
    IF EXISTS(SELECT 1 FROM (
      (SELECT side,object,fga_user,relation FROM pg_temp.kaname_role_stage_tuples WHERE binding_id=carrier->>'id'
       EXCEPT SELECT 'old',value->>'object',value->>'user',value->>'relation' FROM jsonb_array_elements(old_tuples)
       EXCEPT SELECT 'new',value->>'object',value->>'user',value->>'relation' FROM jsonb_array_elements(new_tuples))
      UNION ALL
      ((SELECT 'old',value->>'object',value->>'user',value->>'relation' FROM jsonb_array_elements(old_tuples)
        UNION SELECT 'new',value->>'object',value->>'user',value->>'relation' FROM jsonb_array_elements(new_tuples))
       EXCEPT SELECT side,object,fga_user,relation FROM pg_temp.kaname_role_stage_tuples WHERE binding_id=carrier->>'id')
     ) mismatch) THEN RAISE EXCEPTION 'role tuple compiler differs from staged source' USING ERRCODE='P1034';END IF;
    FOREACH side_name IN ARRAY ARRAY['old','new'] LOOP
     event_type:=CASE side_name WHEN 'old' THEN 'fga.tuple.delete' ELSE 'fga.tuple.write' END;
     -- Реальный emitter получает страницы diff по 256 tuples, а не одну
     -- группу на весь binding. Одна группа может повториться на границе страницы.
     FOR item IN WITH delta AS (
       SELECT DISTINCT value tuple FROM jsonb_array_elements(CASE side_name WHEN 'old' THEN old_tuples ELSE new_tuples END)
       EXCEPT SELECT value FROM jsonb_array_elements(CASE side_name WHEN 'old' THEN new_tuples ELSE old_tuples END)
      ), numbered AS (
       SELECT tuple,(row_number() OVER(ORDER BY (tuple->>'object') COLLATE "C",(tuple->>'user') COLLATE "C",(tuple->>'relation') COLLATE "C")-1)/256 page FROM delta
      ) SELECT page,tuple->>'object' object_name,tuple->>'user' user_name,
       jsonb_agg(tuple->>'relation' ORDER BY (tuple->>'relation') COLLATE "C") relations
       FROM numbered GROUP BY page,tuple->>'object',tuple->>'user' ORDER BY page,(tuple->>'object') COLLATE "C",(tuple->>'user') COLLATE "C"
     LOOP
      payload:=jsonb_build_object('object',item.object_name,'user',item.user_name);
      IF jsonb_array_length(item.relations)=1 THEN payload:=payload||jsonb_build_object('relation',item.relations->>0);
      ELSE payload:=payload||jsonb_build_object('relations',item.relations);
       IF side_name='new' THEN payload:=payload||jsonb_build_object('relation',item.relations->>0);END IF;
      END IF;
      ordinal:=ordinal+1;maximum:=maximum||jsonb_build_array(jsonb_build_object('table','fga_outbox','ordinal',ordinal,
       'origin',jsonb_build_object('family','role.retier','binding',carrier->>'id','side',side_name,'page',item.page,
        'object',item.object_name,'user',item.user_name),'row',jsonb_build_object('event_type',event_type,'payload',payload),'stamp',CASE side_name WHEN 'old' THEN 'decision' ELSE 'transaction' END));
     END LOOP;
    END LOOP;
   END IF;
  END LOOP;
  -- Promotion идёт ПОСЛЕ retier всех bindings. Предикат не сужается: journal
  -- только для distinct OLD/NEW; UPDATE прежней версии 1 остаётся в actual body.
  FOR carrier IN SELECT to_jsonb(b) FROM kaname.access_bindings b WHERE b.role_id=new_role->>'id'
   AND b.status IN ('ACTIVE','PENDING') AND b.revoked_at IS NULL
   AND (b.target->'resources' IS NULL OR b.target->'resources'='[]')
   AND b.grant_capability_version=0 ORDER BY b.id COLLATE "C" LIMIT 100001 LOOP
   scanned:=scanned+1;
   IF scanned>p_rows THEN RAISE EXCEPTION 'role promotion sequence source budget' USING ERRCODE='54000';END IF;
   new_carrier:=carrier||jsonb_build_object('grant_capability_version',1);ordinal:=ordinal+1;
   maximum:=maximum||jsonb_build_array(kaname._authority_binding_journal_v3('access_bindings','UPDATE',carrier,new_carrier,new_carrier,ordinal));
   expiry:=expiry||jsonb_build_object(ordinal::text,carrier->'expires_at');
  END LOOP;
 END IF;
 scanned:=scanned+jsonb_array_length(maximum);reads:=reads+2;
 IF scanned>p_rows OR reads>p_reads THEN RAISE EXCEPTION 'role sequence program budget' USING ERRCODE='54000';END IF;
 cost:=kaname._authority_sequence_reserve_v3('role',maximum,p_reads-reads);
 PERFORM kaname._authority_sequence_freeze_v3(jsonb_build_object('kind','role.mutation','id',new_role->>'id',
  'create',creation,'request',p_input,'stamp',root_stamp,'expiry',expiry));
 RETURN jsonb_build_object('rows',scanned,'reads',reads+cost);
END $$;

CREATE FUNCTION kaname.authority_role_sequence_finalize_v3() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;proof jsonb;ordinals integer[];at_time timestamptz;
BEGIN
 program:=kaname._authority_sequence_store_v3();proof:=kaname.authority_protocol_attestation();
 IF program IS NULL OR proof IS NULL OR program->>'family'<>'role' OR program#>>'{frozen,kind}'<>'role.mutation' THEN
  RAISE EXCEPTION 'role sequence program is absent' USING ERRCODE='42501';END IF;
 at_time:=(proof->>'decision_at')::timestamptz;
 IF at_time<=(program->>'staged_decision_at')::timestamptz THEN RAISE EXCEPTION 'role final clock was not refreshed' USING ERRCODE='42501';END IF;
 SELECT coalesce(array_agg((value->>'ordinal')::integer ORDER BY (value->>'ordinal')::integer),ARRAY[]::integer[]) INTO ordinals
 FROM jsonb_array_elements(program->'maximum')
 WHERE program#>>ARRAY['frozen','expiry',value->>'ordinal'] IS NULL
  OR (program#>>ARRAY['frozen','expiry',value->>'ordinal'])::timestamptz>at_time;
 PERFORM kaname._authority_sequence_select_v3(ordinals,at_time);
END $$;

CREATE FUNCTION kaname.authority_role_sequence_stamp_v3(p_input jsonb) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;
BEGIN
 program:=kaname._authority_sequence_store_v3();
 IF program IS NULL OR program->>'family'<>'role' OR program#>'{frozen,request}' IS DISTINCT FROM p_input
 OR jsonb_typeof(program->'selected') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'role body differs from exact prepared request' USING ERRCODE='42501';END IF;
 RETURN (program#>>'{frozen,stamp}')::timestamptz;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_sa_state_preflight_body_v4(p_id text,p_enabled boolean,p_audit text)
RETURNS TABLE(row_xmin text,row_value jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; account_id text; sequence_id regclass;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'writer_contract' IS DISTINCT FROM '2'
 OR proof->>'purpose' IS DISTINCT FROM 'decision' OR proof->>'kind' IS DISTINCT FROM 'resource'
 OR p_id IS NULL OR p_id='' OR p_enabled IS NULL OR p_audit IS NULL OR p_audit='' OR length(p_audit)>64 THEN
  RAISE EXCEPTION 'service account state preflight requires full decision entry' USING ERRCODE='42501';
 END IF;
 -- Тот же порядок, что у обычного UPDATE enabled: SA row раньше cutoff key.
 LOCK TABLE kaname.service_accounts IN ROW EXCLUSIVE MODE;
 SELECT o.xmin::text,to_jsonb(o) INTO STRICT row_xmin,row_value
 FROM kaname.service_accounts o WHERE id=p_id FOR UPDATE;
 account_id:=row_value->>'account_id';
 IF account_id IS NULL OR account_id='' OR
  (proof->>'mode'='accounts' AND NOT (proof->'accounts' ? account_id)) THEN
  RAISE EXCEPTION 'service account state owner changed' USING ERRCODE='40001';
 END IF;
 -- RowExclusive обязательно ДО key: иначе queued TRUNCATE создаёт обратное
 -- ребро к INSERT, который уже держит RowExclusive и ждёт наш key.
 LOCK TABLE kaname.minted_token_revocations IN ROW EXCLUSIVE MODE;
 PERFORM kaname._authority_minted_cutoff_key_v3(p_id);
 PERFORM subject FROM kaname.minted_token_revocations WHERE subject=p_id FOR UPDATE;
 -- Missing row защищена общим key даже от uncommitted INSERT обычного LOGIN.
 -- Никакой фиктивной отсечки или записи OLD до решения здесь нет.
 LOCK TABLE kaname.audit_outbox,kaname.authority_binding_epoch,
  kaname.authority_policy_epoch,kaname.resource_journal,
  kaname.resource_reconcile_outbox IN ROW EXCLUSIVE MODE;
 FOREACH sequence_id IN ARRAY ARRAY['kaname.resource_reconcile_outbox_id_seq'::regclass] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_backend_pid()
   AND l.locktype='relation' AND l.relation=sequence_id AND l.mode='RowExclusiveLock' AND l.granted) THEN
   PERFORM nextval(sequence_id);
  END IF;
 END LOOP;
 PERFORM scope FROM kaname.authority_binding_epoch WHERE scope='' FOR KEY SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'binding root absent' USING ERRCODE='40001'; END IF;
 PERFORM scope FROM kaname.authority_binding_epoch WHERE scope=account_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'binding owner epoch absent' USING ERRCODE='40001'; END IF;
 PERFORM pg_advisory_xact_lock(1262569298,hashtext(p_audit));
 PERFORM id FROM kaname.audit_outbox WHERE id=p_audit FOR UPDATE;
 RETURN NEXT;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Scalar compilers читают actual locked OLD и допускают только прежние
-- metadata поля либо enabled. Journal payload остаётся каноническим ID-only.
CREATE FUNCTION kaname._authority_scalar_journal_v3(p_family text,p_kind text,p_old jsonb,p_new jsonb)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE source_table text;journal_kind text;result jsonb;origin jsonb;
BEGIN
 IF p_family NOT IN ('metadata','sa_state') OR p_family IS NULL
 OR jsonb_typeof(p_old) IS DISTINCT FROM 'object' OR jsonb_typeof(p_new) IS DISTINCT FROM 'object'
 OR p_old->>'id' IS NULL OR p_old->'id' IS DISTINCT FROM p_new->'id' THEN
  RAISE EXCEPTION 'invalid scalar journal source' USING ERRCODE='42501';END IF;
 CASE p_kind WHEN 'account' THEN source_table:='accounts';journal_kind:='account';
 WHEN 'project' THEN source_table:='projects';journal_kind:='project';
 WHEN 'service_account' THEN source_table:='service_accounts';journal_kind:='iam_service_account';
 ELSE RAISE EXCEPTION 'invalid scalar journal kind' USING ERRCODE='42501';END CASE;
 IF p_family='sa_state' AND p_kind<>'service_account' THEN
  RAISE EXCEPTION 'invalid state journal kind' USING ERRCODE='42501';END IF;
 IF (p_family='metadata' AND p_old-ARRAY['name','description','labels'] IS DISTINCT FROM p_new-ARRAY['name','description','labels'])
 OR (p_family='sa_state' AND p_old-'enabled' IS DISTINCT FROM p_new-'enabled') THEN
  RAISE EXCEPTION 'scalar journal escaped unchanged identity' USING ERRCODE='42501';END IF;
 IF p_old=p_new THEN RETURN '[]'::jsonb;END IF;
 origin:=jsonb_build_object('table',source_table,'operation','UPDATE','when','AFTER','old',p_old,'new',p_new);
 result:=jsonb_build_object('resource_kind',journal_kind,'resource_id',p_new->>'id',
  'project_id',kaname.resource_journal_project(journal_kind,p_new),
  'scope',kaname.resource_journal_scope(journal_kind,p_new),'event_type','UPDATED',
  'payload',jsonb_build_object('id',p_new->>'id'));
 RETURN jsonb_build_array(jsonb_build_object('table','resource_journal','origin',origin,
  'ordinal',1,'row',result,'stamp','transaction'));
END $$;

CREATE FUNCTION kaname.authority_metadata_preflight_v4(p_kind text,p_id text,p_rename boolean,p_audit text,p_patch jsonb)
RETURNS TABLE(row_xmin text,row_value jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE next_row jsonb;maximum jsonb;cost integer;
BEGIN
 IF jsonb_typeof(p_patch) IS DISTINCT FROM 'object' OR p_patch-ARRAY['name','description','labels']<>'{}'::jsonb
 OR (p_patch ? 'name' AND jsonb_typeof(p_patch->'name') IS DISTINCT FROM 'string')
 OR (p_patch ? 'description' AND jsonb_typeof(p_patch->'description') IS DISTINCT FROM 'string')
 OR (p_patch ? 'labels' AND jsonb_typeof(p_patch->'labels') IS DISTINCT FROM 'object') THEN
  RAISE EXCEPTION 'metadata patch is not the closed field mask' USING ERRCODE='42501';END IF;
 SELECT r.row_xmin,r.row_value INTO STRICT row_xmin,row_value
 FROM kaname._authority_metadata_preflight_body_v4(p_kind,p_id,p_rename,p_audit) r;
 IF p_rename IS DISTINCT FROM (p_patch ? 'name' AND p_patch->'name' IS DISTINCT FROM row_value->'name') THEN
  RAISE EXCEPTION 'metadata rename classification changed' USING ERRCODE='40001';END IF;
 next_row:=row_value||p_patch;
 maximum:=kaname._authority_scalar_journal_v3('metadata',p_kind,row_value,next_row);
 cost:=kaname._authority_sequence_reserve_v3('metadata',maximum,16);
 RETURN NEXT;
END $$;

CREATE FUNCTION kaname.authority_sa_state_preflight_v4(p_id text,p_enabled boolean,p_audit text)
RETURNS TABLE(row_xmin text,row_value jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE maximum jsonb;cost integer;
BEGIN
 SELECT r.row_xmin,r.row_value INTO STRICT row_xmin,row_value
 FROM kaname._authority_sa_state_preflight_body_v4(p_id,p_enabled,p_audit) r;
 maximum:=kaname._authority_scalar_journal_v3('sa_state','service_account',row_value,
  row_value||jsonb_build_object('enabled',p_enabled));
 cost:=kaname._authority_sequence_reserve_v3('sa_state',maximum,16);
 RETURN NEXT;
END $$;

-- Старые full binaries не получают late-allocation fallback после cutover.
CREATE OR REPLACE FUNCTION kaname.authority_metadata_preflight_v3(p_kind text,p_id text,p_rename boolean,p_audit text)
RETURNS TABLE(row_xmin text,row_value jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN RAISE EXCEPTION 'metadata exact sequence ABI v4 required' USING ERRCODE='P1036';END $$;
CREATE OR REPLACE FUNCTION kaname.authority_sa_state_preflight_v3(p_id text,p_enabled boolean,p_audit text)
RETURNS TABLE(row_xmin text,row_value jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN RAISE EXCEPTION 'state exact sequence ABI v4 required' USING ERRCODE='P1036';END $$;

CREATE FUNCTION kaname.authority_scalar_sequence_finalize_v3() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;proof jsonb;ordinals integer[];
BEGIN
 program:=kaname._authority_sequence_store_v3();proof:=kaname.authority_protocol_attestation();
 IF program IS NULL OR coalesce(program->>'family','') NOT IN ('metadata','sa_state')
 OR (proof->>'decision_at')::timestamptz<=(program->>'staged_decision_at')::timestamptz THEN
  RAISE EXCEPTION 'scalar final decision was not refreshed after reservation' USING ERRCODE='42501';END IF;
 SELECT coalesce(array_agg((value->>'ordinal')::integer ORDER BY (value->>'ordinal')::integer),ARRAY[]::integer[])
 INTO ordinals FROM jsonb_array_elements(program->'maximum');
 PERFORM kaname._authority_sequence_select_v3(ordinals,(proof->>'decision_at')::timestamptz);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_crud_storage_v3() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT kaname._authority_full_contract_storage_v3();
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_crud_storage_v3() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE expected record;owner_oid oid;
BEGIN
 SELECT relowner INTO owner_oid FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass;
 IF owner_oid IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a
  WHERE a.attrelid='kaname.users'::regclass AND a.attname='expected_login_kind'
   AND NOT a.attisdropped AND a.attgenerated='s' AND a.atttypid='pg_catalog.name'::regtype) THEN RETURN false;END IF;
 FOR expected IN SELECT * FROM (VALUES
 ('membership_mirror_from_user()','d763127654c0d5852aee7f86d8c5f5ea4fa89464c7f1e3c7df9efbace4e6c405',false,'v',false,'preserve'),
 ('_authority_resource_before_write_v3(jsonb,text,text,jsonb,jsonb)','10cfd5fcbe108b1f0b62f688d7ae80b72e34a536593fae3343c730cc0cb82da5',true,'v',true,'private'),
 ('_authority_resource_effect_applied_v2()','3c4ccafbb1580f3dae3f88ca5491fdbed5f99cbe70ea6d394e6b38996fe95028',true,'v',true,'private'),
 ('_authority_resource_write_v2(jsonb,text,text,jsonb,jsonb)','cdb26211660f6fc89ee193516c9bc7cfa3e3bdcd427d3cf71c17c4a047272c2f',true,'v',true,'private'),
 ('_authority_resource_side_v2(jsonb,text,text,text,jsonb)','09f8a713bf8e2a59ec0051910a49f5df93dec5bc5c776271c2f1a54dbb1eb8f1',true,'v',true,'private'),
 ('_authority_crud_anchor_capture_v3(jsonb,integer,integer)','2dee8b172ebd3b228b5c6cc4dec189feae30db2c1c9a4bc98752525025d823c7',true,'s',true,'private'),
 ('_authority_crud_authority_graph_v3(jsonb,jsonb,integer,integer)','3ce64fcc9997385efdac3a546dc44ab66e0b5022ec5d9cb5de8d5bfdcffaec9d',true,'s',true,'private'),
 ('_authority_crud_aux_capture_v3(jsonb,jsonb,integer,integer)','cbe93565f4de42904c6a0e2434db9a21ce0d528902d2a3908a2fec92cb821318',true,'s',true,'private'),
 ('_authority_crud_aux_write_v3()','5b549be379610152a2c2efc86836606fb82c298d885be0125cee3b535cf8cd32',true,'v',true,'private'),
 ('_authority_crud_aux_images_v3(jsonb,jsonb,jsonb,timestamptz)','f7cf945fa67c0bf19182121b6e31655f1939257dabac972618a15cd6fa9eda8b',true,'i',true,'private'),
 ('_authority_crud_aux_statement_v3()','6f1ea38ba87217ba6a1e13ace6c1de40c3a9f05cfe6ab1765addbe7541c22f40',true,'v',true,'private'),
 ('authority_resource_crud_capture_v3(jsonb,integer,integer)','4ed7f709885d233f48bfd4ff0ced2cabf6b0ec6db07906156530bb6120391f32',true,'s',true,'export'),
 ('_authority_crud_merge_tables_v3(jsonb,jsonb)','beb1fb11dc689c0b6e22411c4edd3ac6025b76fa6bdb74f49bad95b27fa9c1ae',true,'i',true,'private'),
 ('_authority_crud_capture_v3(jsonb,integer,integer)','794f687a5c86e36d6ff91984e7942497dc6765fa3c9c685b514ac8a406cf8182',true,'s',true,'private'),
 ('_authority_crud_cascade_capture_v3(jsonb,integer,integer)','a155c5bf5c0d2e81b9b2b2d3d85f5cb234a3cc162585041237c4e9f6257fd73c',true,'s',true,'private'),
 ('authority_resource_crud_body_values_v3()','d7440d3bbf47f4dbc2b8e254cdfc248b1d79d6dd839de9fb2243e8fc4d76158b',true,'v',true,'export'),
 ('_authority_crud_step_complete_v3(jsonb,integer)','6a1951e0f4eb8b4dcd3a417f68938ac5e4771f04b1cf085938994dc45130e146',true,'v',true,'private'),
 ('authority_resource_crud_step_v3(text,jsonb)','51b2b069757a6860df25f6dcc47558881ce21accf0a5b2ce0f813cd55d37aa50',true,'v',true,'export'),
 ('authority_resource_crud_lock_held_v3(text)','2101acd7137f106b763dbdccf69f7f257ccd8650bc89e7f1d191132fffb51f6f',true,'v',true,'export'),
 ('_authority_crud_require_completion_v3(jsonb)','9a9d56a95bbb255d52eeddf6c07a6f5e5663490ded6d8a558d097848a885d75c',true,'v',true,'private'),
 ('_authority_crud_command_v3(text,jsonb)','c5002541ff2bbabedbcd9d74b6adc04b13a6a36833eefd1631f875d47652eb75',true,'i',true,'private'),
 ('_authority_crud_structural_v3(text,text,text,text)','00d37afb9a7b7c9d4534df79f313c14e13fc16a1756d368d85ca2e5f4d939c13',true,'i',true,'private'),
 ('_authority_crud_command_plan_v3(jsonb,jsonb)','ea252acb7bcebc7c96da591416609deb3b606d01eeda6a3a32e911a0e77af3d1',true,'i',true,'private'),
 ('authority_resource_assert_body_v2(jsonb)','3c9b0e789716d0e0c9d50e98b80ea7e90746703425e13dc92246b210d5c68410',true,'v',true,'preserve'),
 ('_authority_resource_require_completion_v2()','bbcfca0b3d5ff59ad273695dfed2451f1ff37bf4030f8f7083415396dafee0e6',true,'v',true,'preserve'),
 ('authority_resource_fold_body_v2(text,jsonb,timestamptz)','05f1c814b7e2ae4480d18581c24c9c427523798191abb88c1761a4f923997507',true,'v',true,'preserve'),
 ('authority_resource_prewait_v2(jsonb,integer,integer)','e835d0c4f015334d151c7a902e7cb5c10a8f7d5d2ee2c4d6fad478bd558e5f83',true,'v',true,'preserve'),
 ('_authority_crud_image_v3(integer,text,text,jsonb,jsonb,boolean)','967a84fb10617c3a5f376d63aaf2903538edc5fe1548150b307bae33a70ee3f9',true,'i',true,'private'),
 ('_authority_crud_domain_images_v3(jsonb,jsonb,jsonb,timestamptz)','2e4cf1562674897a696483469505925ba5862b6fe0422f663b330eb96f237b9e',true,'i',true,'private'),
 ('_authority_crud_intent_v3(jsonb)','e62f470c0c69a980308bec36a35f515609cb8fea56c79ec7632ac654a43e0f49',true,'i',true,'private'),
 ('_authority_crud_manifest_domain_v3(jsonb)','72c12f24e9c426b44fcc41b7690423a30675175589cd2ea6554beb48ad555387',true,'v',true,'private'),
 ('_authority_crud_fga_rows_v3(jsonb,text,jsonb,integer,timestamptz)','d84adbcbed2a7a07b7080ddd83eaab375144edbdbb4b4ad9c50ffce92012fc5c',true,'i',true,'private'),
 ('authority_crud_fga_id_guard_v3()','cc6115bf7fafa0e7a70da14aa14db4232644f3a10d1ba34b1df131d93c616a49',true,'v',true,'private'),
 ('authority_crud_fga_id_applied_v3()','12aadb134df61a6f55b28252be5d22773e70f7b75f0a2117577faa2565a99594',true,'v',true,'private'),
 ('_authority_crud_fold_capture_v3(jsonb,integer,integer)','4324197370450be1edcfc6de9b822fd24e838932135c2c3861c438fa62fe5149',true,'s',true,'private'),
 ('_authority_crud_fold_images_v3(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','c64f0e0be50cf2b6954b4912201dd238acf768d31eb26578b4155c1f0f697b03',true,'i',true,'private'),
 ('_authority_crud_graph_index_v3(jsonb,jsonb,jsonb)','6402a8ddbf72280f803ced92f33536a500e49252d15159223bd8bafa98c694dd',true,'i',true,'private'),
 ('_authority_crud_journal_capture_v3(jsonb,jsonb,integer,integer)','0e1271f048a93d4632fc6e30346b1a10682e619b4077405048a495840c199fda',true,'s',true,'private'),
 ('authority_resource_crud_journal_value_v3(jsonb,jsonb)','801f9974286e1bd23fb9559e5abf3da66c3fa9ebfd18f27fb18984b0762c6e0d',true,'v',true,'export'),
 ('authority_crud_journal_applied_v3()','d8238730f4bb3d9754ddc7108ad4dc70b348494f51b2dea1567b06cd69e9c7e2',true,'v',true,'private'),
 ('_authority_crud_journal_plan_v3(jsonb,jsonb,jsonb)','e8af1dadee7c4d3e8bf7790a0464ac9c8319bbaac789bb15aec5ef4ceeb56ea6',true,'i',true,'private'),
 ('_authority_crud_journal_rows_v3(jsonb,jsonb,timestamptz)','e37fb29c6f7ff41ab6c0d15c3dfc0da196e7177c36dc848e0dc304b445d14a80',true,'i',true,'private'),
 ('_authority_crud_unique_key_v3(text,jsonb)','b7407a60f467821e6fe19c697ea37079807dbd5bed88c51a4ad645de731cf5b3',true,'i',true,'private'),
 ('authority_crud_unique_guard_v3()','5e8dbb8ba000bde51e8aa64c8e2fb708666f4822bb677a059adc623b0b45eb7d',true,'v',true,'private'),
 ('_authority_crud_sequence_wait_v3(text,integer,integer)','3b40419c3cbb8e156a2926933f7d7075a93129fa34c2294122dcd04f9cf76edf',true,'v',true,'private'),
 ('authority_crud_sequence_guard_v3()','3b536b907c2a5ccb5cb3444463da506797202289e4091404cacf736cda2e37d8',true,'v',true,'private'),
 ('_authority_crud_key_maximum_v3(jsonb,jsonb,jsonb,jsonb,timestamptz)','e3ad0cc2300061a6630225ec8956cee4b552f4ff8d9c1804f0dbfb5af0b12692',true,'i',true,'private'),
 ('_authority_crud_lock_rows_v3(jsonb)','e04ceccbff7121da453fc79b071db7d7c3f54b8425cda74f53520143641a22d9',true,'i',true,'private'),
 ('_authority_crud_lock_plan_v3(jsonb,jsonb,jsonb,timestamptz)','85bef48d34921afb7fd0659fe6554288f47db763cd0c872dcaa92cb713065d85',true,'i',true,'private'),
 ('_authority_crud_manifest_images_v3(jsonb,jsonb,jsonb,jsonb)','f1fc57972e2b2575a0a323090cc8560ad975b5d4a7f061a8b28faa2ab6ba6784',true,'i',true,'private'),
 ('_authority_resource_crud_materialize_v3(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','b3e2ac3c0942fa7957aa6ecb234c39b388dc80881cdd23545c774cfd05112dff',true,'i',true,'private'),
 ('_authority_crud_maximum_v3(jsonb,jsonb)','62f166faf92695eccfc65f5e979ac33b7610a9fb0b640274a361300039541ce0',true,'i',true,'private'),
 ('_authority_crud_pack_v3(jsonb,jsonb,jsonb)','ab5603fc90f193b60e06d29823842f43967d1515ba1d3eaca6fbde97099d6c6c',true,'i',true,'private'),
 ('_authority_crud_physical_v3(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','81c8fd09ea95dd337e3d56928513de55a24eeb981695185c58c1db06f6c06f24',true,'i',true,'private'),
 ('_authority_resource_crud_prepare_v3(jsonb,integer,integer)','ee22d1a0007376a262864613f3cef81893f76d70f2ceae94fe2e672273914aa4',true,'v',true,'private'),
 ('_authority_crud_relation_wait_v3(jsonb,jsonb,jsonb,integer)','424927c26adc58d65a55a4567766054c378f1340662d0401146e5e2dac2f0bad',true,'v',true,'private'),
 ('_authority_crud_reserve_v3(jsonb,jsonb,jsonb,integer,integer)','a9e7a60de752dcf436571f457c67de751439e77276005238dab9abed9ef9049b',true,'v',true,'private'),
 ('_authority_crud_scope_capture_v3(jsonb,integer,integer)','7cd250c6e17d5c41737c1afebca7576744bae05ec46af01136678c515e23f5e5',true,'s',true,'private'),
 ('authority_protocol_statement_guard()','457d0003223d4ad53047310a311f677f94852a6aefd39523d38398b075613da8',true,'v',true,'preserve'),
 ('_authority_resource_crud_store_v3(jsonb)','b3c4cf46195b7a32a2454911b29c8ea51a0e37741ca98380890e911f4e765135',true,'v',true,'private'),
 ('_authority_crud_tuple_wait_v3(text,jsonb,boolean,integer,integer)','8ebecbc122a5558910017569ac3ea927ad37ea4066dec179a253807b4c5d9574',true,'v',true,'private'),
 ('_authority_crud_unique_wait_v3(text,jsonb,integer,integer)','ded94e6b1bf461dfaf9753a2e71dc73f45f474826b1d7a2f950e097c455629b0',true,'v',true,'private'),
 ('_authority_crud_json_keys_v3(jsonb)','42d2e6afa061f7c443be4e75a6fe3742414583923d2929ba77250c45ccb239d3',true,'i',true,'private'),
 ('_authority_crud_write_metadata_v3(jsonb,jsonb,jsonb)','7bdfa746b1066e54eccfffa3067fa923b09a1364d883c444b19dc5c873181af4',true,'i',true,'private'),
 ('_authority_protocol_attestation_v1_body()','2c6a618c91d3b7fff8a5e23734d8d7815d6c38cb9b82adacd2e472202584fc54',true,'v',true,'preserve'),
 ('authority_grant_mutation_preflight(text)','8ef00bb883b777d2abf07b0f43589dbd5fad7ac01c9bae8b3f22821e549060e8',true,'v',true,'preserve'),
 ('_authority_binding_scope_tier_v3(text,jsonb,jsonb)','81cacba8227f605eaf666624c9ceae52808ddc086b87d258bb33a95611a412bb',true,'i',true,'private'),
 ('_authority_binding_journal_v3(text,text,jsonb,jsonb,jsonb,integer)','9a34cb8196ba7de482bd9270115e1770a6210c9745b235703cb50cb6d0cbea34',true,'s',true,'private'),
 ('authority_binding_sequence_prepare_v3(text,jsonb)','bc276ed48b9a8e9d4eeb6cb472bfbda1a1a400dd8b34992f391f9423143272fc',true,'v',true,'export'),
 ('authority_binding_sequence_finalize_v3()','51e4b66f099b3b7c0a5f144af2ae540b5dbe72d00c52a170cfc7ec2e43f87fdb',true,'v',true,'export'),
 ('authority_binding_insert_stamp_v3(text)','2cf09a04b6655fe144aa8bcf9d8d5f032cee57173bf45dd3cd19c08def9a29f1',true,'v',true,'export'),
 ('authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)','36110eaf94450a319c4bb49eede73ab21c6df8fd25ad692620c889b6538fc944',true,'v',true,'export'),
 ('_authority_binding_stage_snapshot_v3()','9e9d561435b0f86c51aec452283505184beee36e1dc02f4af708590955d2eebf',true,'v',true,'private'),
 ('authority_binding_stage_sequence_prepare_v3(text,text[],jsonb,integer,integer)','149e79febcfb21805027ec74dc740b85392372b72842f9d29d95f86ff935c15c',true,'v',true,'export'),
 ('authority_binding_stage_sequence_finalize_v3(text)','1f3a07c19d6385b555b3eec2967484b65d3d27aef9e340162520f41c3fbe624e',true,'v',true,'export'),
 ('_authority_binding_stage_source_v3(jsonb,oid,integer)','da7d9a57254d57e76becd34722bd349902ad6ed6a5662eac7db561efd21ecd40',true,'v',true,'private'),
 ('_authority_binding_stage_coordinates_v3(jsonb,text[],boolean,oid,integer,integer)','3b17c2eb7e40b1d5a6eb09af09fd0c1e9c5c4d8b4678e7537d94abad2e668c22',true,'v',true,'private'),
 ('authority_binding_withdrawal_sequence_prepare_v3(text,text,text,integer,integer)','c78567e12d9c2ac4dabed52f4ff57d538266787beadeba6c855bffe44281619f',true,'v',true,'export'),
 ('authority_binding_withdrawal_sequence_finalize_v3()','7ed02bf2fbfd3107060c4ca7815b99593d90400903676c8ccb32657d68511ea6',true,'v',true,'export'),
 ('authority_cluster_admin_preflight_v4(text,text,text)','dee9de21827355b15b060104dc7232b3f1e784eed23b074c24295ea6e2e40a0d',true,'v',true,'export'),
 ('authority_cluster_admin_preflight(text,text)','2bda979c851a1a59d5ba97dc79c2eff3a14c404f1e50ca7975638f4fafae9700',true,'v',true,'preserve'),
 ('_authority_metadata_preflight_body_v4(text,text,boolean,text)','d547aed450a42acf12a3e1a7f565a97dad4fec25a3ee30049e70275e4d261209',true,'v',true,'private'),
 ('_authority_sequence_freeze_v3(jsonb)','dbb50139a60af61a07690037c20b62c7d0b3dbf6a4cdff1e05307efca6836ef4',true,'v',true,'private'),
 ('_authority_sequence_bind_v3(jsonb,timestamptz)','4e8241c16905238f8f5064a12537cf5ee0892e596d89f2aa8d8a92f6dd31359c',true,'v',true,'private'),
 ('_authority_sequence_default_v3(text)','55bbb442c7aefc7e080eb6dc33b7255444438eb653d9d1f493986315aa8c3196',true,'v',true,'private'),
 ('authority_resource_journal_id_v3()','1890af3f773bb503aa2d4324c56ed4925c1ffac60d36181cc0d7c579f1e8ae18',true,'v',true,'export'),
 ('authority_fga_outbox_id_v3()','75b2ab0cad8f6111bca3dc5bd119f87dbbffa0dbed74480f172aa0f465b672bb',true,'v',true,'export'),
 ('authority_sequence_program_applied_v3()','6a748b5a88787b5c9c7c59b0ebdd0e8244901881b91677cdd123b22527880610',true,'v',true,'private'),
 ('authority_sequence_program_completion_v3()','055164a539031177a7605113484f5667702c9074b84d03ab1a827cd614b66e35',true,'v',true,'private'),
 ('_authority_sequence_expect_v3(text)','b1c9d01de1052d58906c288c676bac307fcee06c5648745ede4cc0c816bfe966',true,'v',true,'private'),
 ('_authority_sequence_expected_v3()','e318cafb455438dd9a40e3c2cec7cc2d88daedf4307dd1e43248175005ab045b',true,'v',true,'private'),
 ('authority_sequence_expectation_complete_v3()','aef5c1e0bfa60d5587aa8c0f342b3f5df1166a1a699af56019f5bdf36e856c99',true,'v',true,'private'),
 ('resource_journal_emit()','76c8f397a387cb6699642e1d3aa56c2c61f371245eb28f56b14ed19c1d1faeba',false,'v',false,'preserve'),
 ('resource_journal_emit_member()','4dfca2c401a428e6b4ad984b99aae3a34404999ea36ed26b14c70b2ceb1d4053',false,'v',false,'preserve'),
 ('authority_sequence_origin_v3()','6963f498b25abc1459fcb33eda43bca07b8e3602cfcae23c125601b3b5b9d747',true,'v',true,'private'),
 ('authority_prepared_journal_value_v3(jsonb,jsonb)','ec8e01085af732139c0478e82abd29817d25ca342afa4963d96491f8daca4017',true,'v',true,'export'),
 ('_authority_sequence_excluded_v3(oid)','eb4872a7f8c5bb7c40564e17fcc1928eac64bdbd8ac2e5609d261bd9ad36594b',true,'s',true,'private'),
 ('_authority_sequence_shape_v3()','614125faa823e6f14b0d2f58f2a6ed7ea9a5239febef2dd83b7ba4508f0f9014',true,'v',true,'private'),
 ('_authority_protocol_snapshot_v3()','f994c63975e86be78b2854a4f51aed55e615ad2c380b0f58fc1e0390662fc30a',true,'v',true,'private'),
 ('_authority_sequence_probe_v3()','2e2a3266993eadee820fba438960cde53cf25cd05a4e806661e8d62664f075c3',true,'v',true,'private'),
 ('_authority_sequence_header_v3()','375b51310e57a7016673ba26f5b9925d59e67a2599ba74fe9c11d3f5bf9c70f5',true,'v',true,'private'),
 ('_authority_sequence_publish_v3(jsonb)','013f8260baa0607516e57b791a92897d3d4bb143a401dd056166d1fbf70d3128',true,'v',true,'private'),
 ('_authority_sequence_store_v3()','adca627a6c7ce9b1ee755a231793134d5ebcc372f370c694cbac3f067fb471d2',true,'v',true,'private'),
 ('_authority_sequence_reserve_v3(text,jsonb,integer)','ced42594fe0db1104e09efa082898d3ffdf833cc18dc42e92f26de8d28e3fcc8',true,'v',true,'private'),
 ('_authority_sequence_select_v3(integer[],timestamptz)','7f9ce472e9d23f7a6182685661f2964bdc0266fefe1a59b9228d9908b171bb09',true,'v',true,'private'),
 ('_authority_sequence_claim_v3(text,jsonb,jsonb)','18cdb51c9e44fa944b355cadf1abcb291eba062ca09f3221118bcd60d736c740',true,'v',true,'private'),
 ('_authority_sequence_applied_v3(text,bigint,jsonb)','0a4c24ded6b6aad09fd077e4a1ad8d40dee440c4e27e44dc20e4300bfc0a5a7d',true,'v',true,'private'),
 ('_authority_sequence_complete_v3()','e3044a2938caa4b1e83320b8133c7241c5970b7883d1471cdf25bb353d2c02f4',true,'v',true,'private'),
 ('authority_resource_finalize_v2(jsonb,integer,integer)','f68d6ef701f2e730fd10d2c65aec966d04aceaf54465ac87b684da8157985f0c',true,'v',true,'preserve'),
 ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','47aae35f146c1d05bf9f5f52f9f7b929d69d91f64b39844fd697530c467af440',true,'v',true,'preserve'),
 ('_authority_resource_object_program_v2(jsonb,timestamptz)','97f643954fbef4036c37240711c9ce9650045102c77bce1d5e8396d89a4c8464',true,'i',true,'preserve'),
 ('_authority_resource_object_sequence_prepare_v3(jsonb,integer)','bbf639e8b58fee3ee80ce322a7946cd5ae4a3f0a84804270117a369914fc5153',true,'v',true,'private'),
 ('_authority_resource_object_sequence_final_v3(jsonb,timestamptz)','4a5b05945442bea77d6ac8a8623036f22e1a1eaaacde14c24aaad5cb6e20c2fe',true,'v',true,'private'),
 ('_authority_resource_physical_relations_capture_v2(jsonb,integer,boolean)','e01481c788b47322941e6c6753d9d38e44e1bdcee973a8fb6292aed42d9ce54f',true,'v',true,'preserve'),
 ('_authority_resource_registration_sequence_prepare_v3(jsonb,integer,integer)','0d6ab18cc9cac1395df175c0c91912737bf8e78464d46da0c385e31aa36c9b66',true,'v',true,'private'),
 ('_authority_resource_registration_sequence_final_v3(jsonb,timestamptz)','27a740d1b160e5eae00567166293f738f7f6131e58998de2f7784629d2011e29',true,'v',true,'private'),
 ('_authority_resource_registration_direct_prepare_v2(jsonb,integer,integer)','ad9230edf198624a3d9caa84ee5a5a9954b79cd9afa58b1e0b64b60eb3dd2807',true,'v',true,'preserve'),
 ('_authority_resource_unregistration_prepare_v2(jsonb,integer,integer)','3b4c2286943cb21eb7a8f3f9875bd43a9da46c92268bb2838c30c01102df681d',true,'v',true,'preserve'),
 ('authority_role_stage_epoch_lock(text[],jsonb)','2f4e6d4569577abe84313594f72e973d8b5fb63ac2adbd5605640751c7bc5021',true,'v',true,'preserve'),
 ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','5d47e24c50baaa1619a6cfb2198255c248fec06d535e13febacf7078c6aeae64',true,'v',true,'export'),
 ('authority_role_sequence_finalize_v3()','4b1b5626bc90a7826a4bed308befc83c4e688b636f9dcd59d7446811f20ec891',true,'v',true,'export'),
 ('authority_role_sequence_stamp_v3(jsonb)','1a76eb48aa2c75c7213b7e01fe7530bfe859348a0fb8cf3cb0d79be83e9dd1f8',true,'v',true,'export'),
 ('_authority_sa_state_preflight_body_v4(text,boolean,text)','866552ed304b028241b3cf523869fa39104810a924ccb14661684689b76a95f5',true,'v',true,'private'),
 ('_authority_scalar_journal_v3(text,text,jsonb,jsonb)','b6c669cf2485b11b8a84bf8935d30b1707805f7c043c8abfba1c77476eedf4ab',true,'s',true,'private'),
 ('authority_metadata_preflight_v4(text,text,boolean,text,jsonb)','28de0a19487c8105f8ae7495cd1c195a84349fc2e5604493692bbcfaa34136bd',true,'v',true,'export'),
 ('authority_sa_state_preflight_v4(text,boolean,text)','6fbed0052196e4ad096c6047b1e018633760ea80f9edd7c722fb00b7b60900dd',true,'v',true,'export'),
 ('authority_metadata_preflight_v3(text,text,boolean,text)','ea89b06dc47ce62579a99026522c1d8dd4c0edc585922c71ca77c9ea11b07ed3',true,'v',true,'preserve'),
 ('authority_sa_state_preflight_v3(text,boolean,text)','980a05e9e1dc6973b93ba6694ea376a70efaa22a4639e5b762b425b81dbad3f7',true,'v',true,'preserve'),
 ('authority_scalar_sequence_finalize_v3()','c403ea97073dc0833cacdbfbd79691ccd1b11a6b0ca4c71fb2a73112e7d58be8',true,'v',true,'export'),
 ('authority_crud_storage_v3()','f2e0fb99aa034aaae63126e7f6b621fb8da6deb7b8ec21e0852f73bcf2e1e0fe',true,'s',true,'export'),
 ('_authority_resource_ancestor_graph_v2(jsonb,jsonb,jsonb)','0169e22d120961d1959b1eb87b684ab0ecf20c1cdb7c6e4f35289ebe5ce606b7',true,'i',true,'preserve'),
 ('_authority_resource_audit_capture_wait_v2(jsonb,integer,integer,boolean)','48833909f08147b697650810555b86266f9f7b6b0c41951fee89ba22ec25fd97',true,'v',true,'preserve'),
 ('_authority_resource_audit_plan_v2(jsonb,jsonb,jsonb)','f11cd1f48fdf0634bc288b523beb1758e66fbfab54fe020abb580cd0eaa99514',true,'i',true,'preserve'),
 ('_authority_resource_audit_wait_v2(jsonb,integer,integer)','29066819dd86fb4512a79fc4b8d30f88e95df89a74099e91471b39548efeb3e3',true,'v',true,'preserve'),
 ('_authority_resource_binding_candidates_v2(jsonb,jsonb,text,text,text,boolean)','0dd211dcb360329fa856f8c14692b50169668f73e2c03fd90aea3d3a0d7737b0',true,'i',true,'preserve'),
 ('_authority_resource_binding_certificate_v2(jsonb,jsonb,text,text,text,boolean,jsonb)','ec4d5deaf2df7982eba06a3350b0ae874c7179af6b41912fae3ed4d93e5c9386',true,'i',true,'preserve'),
 ('_authority_resource_bundle_catalog_v2(integer,integer)','eab6ae0b0d35773cd85b32a52758804f843eb49b289c6296d44df34e92fa3842',true,'v',true,'preserve'),
 ('_authority_resource_capture_index_v2(jsonb,integer)','eb03f80f2dfdf2627a2f3a6268516126a758edd739b538dffbcdfca1b4a0068c',true,'i',true,'preserve'),
 ('_authority_resource_carrier_graph_v2(jsonb,text[],text[],text[],text[])','25cfe0b7f33582cfbee3399700901690952f97cff1e63d989ddde23176f42c80',true,'i',true,'preserve'),
 ('_authority_resource_carrier_scopes_v2(jsonb,jsonb)','0440ef56bc4069d6e1029e94dbab6acea6bddf7b5de88fc109f09f743599b60c',true,'i',true,'preserve'),
 ('_authority_resource_catalog_capture_wait_v2(jsonb,integer,integer,boolean)','c2dce8593b8f7616af573591ed0d439f822054f78f96de78ff8fc20d59efde18',true,'v',true,'preserve'),
 ('_authority_resource_catalog_wait_v2(jsonb,integer,integer)','6231367fd8a56cec22aed190ae2eef6dd8b3f93b2db1a0d8810ca6d9d5d53e97',true,'v',true,'preserve'),
 ('_authority_resource_contained_v2(text,text,jsonb,text)','e8cd715375fb48ff94738b78d82f00087fa548634ca3ebc43edd45dd54c8a758',true,'i',true,'preserve'),
 ('_authority_resource_coordinate_certificate_v2(jsonb,jsonb,text,jsonb,jsonb)','05ae24720db11aeb157d0078be92678753fcf98bec6d695e0536d4e184eb43f0',true,'i',true,'preserve'),
 ('_authority_resource_encode_proposed_rules_v2(jsonb,boolean)','e2f7cab577d72eedcbf78ccfbe3c3109cf1414d90617a036a95861ab199bbacc',true,'i',true,'preserve'),
 ('_authority_resource_epoch_wait_v2(jsonb,jsonb,jsonb,integer,integer)','52e0cc8f44374d68a98450683564534073a08be0727c31e8846757f906910129',true,'v',true,'preserve'),
 ('_authority_resource_grant_reference_v2(jsonb,text)','df8c0b484673605fdf285a40ab35045b49f622ed66da6d56962846d1228009b4',true,'i',true,'preserve'),
 ('_authority_resource_grant_rule_fp_v2(jsonb)','eaa4bee66714be005240c085088d71cc3fbdb1cb95575c892cfcadd7aedd9671',true,'i',true,'preserve'),
 ('_authority_resource_installation_eligible_v2(text,text,text,text,text,jsonb,timestamptz)','697e605e233cfc83f3f6a75f230e5ee309a0e365d854bb3eae46f73d6d41cbbf',true,'i',true,'preserve'),
 ('_authority_resource_installation_wait_v2(text,text,jsonb,integer,integer)','cdc2aade908f9ed07ef42c20be0ad8f7b92f77bd51bd5f4c6a7080b0671e57db',true,'v',true,'preserve'),
 ('_authority_resource_key_array_v2(jsonb,boolean)','ec975c9c1dd185c9582596cbc96c7916c26f93b20d91c7c9eefb5ef22755d7a1',true,'i',true,'preserve'),
 ('_authority_resource_ledger_obligations_v2(jsonb,jsonb,jsonb,jsonb,boolean,boolean,integer)','d0ac1b9d8ab0c3c1821baaef668de1bb12c6edb0beddb3f4942874d433f4f2ff',true,'i',true,'preserve'),
 ('_authority_resource_manifest_create_v2()','b9ee82cbaa043c831c36e612387f616941b7cf028e13fb6b215da6679e486ccd',true,'v',true,'preserve'),
 ('_authority_resource_manifest_v2()','a80529dcdf4cb68395a9311f2f7b737fb467f0768c5b8a7e4488679bd5f3c63f',true,'v',true,'preserve'),
 ('_authority_resource_match_wait_v2(jsonb,integer,integer)','6ff5dc168529251407ee765ab0f1a53e4089a124e101128f481ea5382ba3e626',true,'v',true,'preserve'),
 ('_authority_resource_materializable_types_v2()','de8eb0540e5ee90a586412bc1503c3c16c24ba9f99359cae97ed7489c8151136',true,'i',true,'preserve'),
 ('_authority_resource_materialized_types_v2(jsonb,integer)','a1b18cbee25c6da9fa6cbd017b0dbcd69eaa5c692065d0856d6b65cadaad4bac',true,'i',true,'preserve'),
 ('_authority_resource_member_obligations_v2(jsonb,jsonb,jsonb,jsonb,boolean,boolean)','4cda1e3112578a85f8b85c11a17a6d68126eb4eebea678c542fe5eee2e7a2d58',true,'i',true,'preserve'),
 ('_authority_resource_module_identity_v2(text,text,text)','b8c934a9370e413464b0577108ed9e69b42898308851b003ad2f646bd0e94fc8',true,'i',true,'preserve'),
 ('_authority_resource_nested_rows_v2(jsonb,jsonb,integer,integer)','3af0e8ae4591ff8be128e912062f921974d9d7ec9202c8ce1f4a6de651fed360',true,'v',true,'preserve'),
 ('_authority_resource_object_candidates_v2(jsonb,jsonb,text,text,integer)','dd5be24069ae63a2c946ed9a64344a5191f1f85994ce561139853d483d92fab4',true,'i',true,'preserve'),
 ('_authority_resource_object_certificate_v2(jsonb,jsonb,jsonb,jsonb)','9d0b5419a24502e9abfa42b50fed23be08ed5d349af73c6eb79896b17712c8e3',true,'i',true,'preserve'),
 ('_authority_resource_object_fold_v2(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','a3b9e3f7fd865d129ee4a9140a5795627e7697e9aa8cd4003ba5cc6a92f5b06e',true,'i',true,'preserve'),
 ('_authority_resource_object_graph_v2(jsonb,text,text,text)','7b51494829379bfdd91f4853099642f2e57c88ad887912e1656c5f5669a7ca76',true,'i',true,'preserve'),
 ('_authority_resource_object_manifest_images_v2(jsonb,jsonb,jsonb)','940501419f3759706e6e56fb6626e61a6896c247ffd3151c5283c0360719ab35',true,'i',true,'preserve'),
 ('_authority_resource_object_materialize_v2(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','01559b0be95e275e46e33b0b00028c80e611b97a64fbc8eb85b0910643dd2505',true,'i',true,'preserve'),
 ('_authority_resource_object_maximum_v2(jsonb,jsonb,jsonb,jsonb)','bf2c9287fdf43dac1cc03a9c62f0a665dfda01792c54fd6440f061ec9343204c',true,'i',true,'preserve'),
 ('_authority_resource_object_physical_sources_v2(jsonb,jsonb)','8beafc61826cbc195149bf41e1ca3402c4f794088fb81da73e91af089fcb00d3',true,'i',true,'preserve'),
 ('_authority_resource_object_physical_v2(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','98f24f2154bfc6e60611130a825cf0eb93efb6631ed36ba142f8c9a2eb0cae61',true,'i',true,'preserve'),
 ('_authority_resource_object_store_v2(jsonb)','761cb220c553c2d519c5adc6fc14b6ab4675779b205dbc529982863023ac1b5a',true,'v',true,'preserve'),
 ('_authority_resource_object_write_keys_v2(jsonb,jsonb)','55621c02ba3a899e93d5c41eddef68dd231c37500d740e2ff09bfffcb8529072',true,'i',true,'preserve'),
 ('_authority_resource_ordinary_member_v2(jsonb,jsonb,text,jsonb,jsonb)','e22a387229f36c3ff81806752df50a0a0b5e03f2d8a66df1f0482180e17b5305',true,'i',true,'preserve'),
 ('_authority_resource_physical_relations_wait_v2(jsonb,integer)','86d6bd4c42c79ee3d6dc95ea2317113fcf99849f0445a03307e598abffecb3f2',true,'v',true,'preserve'),
 ('_authority_resource_predicate_maximum_v2(jsonb,jsonb)','54f35fa496cbd4bbb0ff0d7f838eab7e3dbb1bf17cf5b3ea8a54e55223e68a46',true,'i',true,'preserve'),
 ('_authority_resource_preheld_key_v2(integer,text,boolean)','77d85a114d79fb9d60470f0bdd63e2f688d5164fd5a225c5cebef10e43da78ea',true,'v',true,'preserve'),
 ('_authority_resource_projected_capture_v2(jsonb,integer,text,text,text,boolean)','782d8002dc7498b18696afa46da3429774cbcd9580030b46bb76d6ce97328267',true,'i',true,'preserve'),
 ('_authority_resource_projection_v2(jsonb,text,text)','79fb1eeb6681835031a23733e52c34ca00e1d13bfde63655dfdcfe1c663db0bf',true,'i',true,'preserve'),
 ('_authority_resource_publication_direct_program_v2(jsonb,jsonb,timestamptz)','753c099113766391b73c537756b40729a0e39111983d8fe2b1803407918bd25e',true,'i',true,'preserve'),
 ('_authority_resource_publication_fold_v2(jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz)','2162e671105cd0d167abc538791192b7e8c6861e943f9ac60bba6294254f9058',true,'i',true,'preserve'),
 ('_authority_resource_publication_images_v2(text,text,boolean,timestamptz,jsonb,jsonb,timestamptz)','0a343a95b30ad5ec1de4aaaf900d74e0fef4c44506ca5c406ec9ea7e7916c53a',true,'i',true,'preserve'),
 ('_authority_resource_recipient_verbs_v2(jsonb,jsonb,jsonb,text,boolean,text,boolean)','f6080aad1d9dc4a12c26513ba2638f5fde3f959a79ce83a88a1c16e522b42c29',true,'i',true,'preserve'),
 ('_authority_resource_reconcile_wait_v2(integer,integer)','2e5af4934a850ef95f1a333ad71694bd4f27fa51f1b0de19b670ed9f3ca5d8fa',true,'v',true,'preserve'),
 ('_authority_resource_refusal_certificate_v2(jsonb,jsonb,jsonb,jsonb)','6839592d4eb1336e5deeef0eec6f2367c14f0717c63f575c4be6b03352563350',true,'i',true,'preserve'),
 ('_authority_resource_refusal_materialize_v2(jsonb,jsonb,timestamptz)','fc6cef31e2f28cb7b6bf3d5b6f95aa601ac1caf89a55e7405af0c84a302d1eab',true,'i',true,'preserve'),
 ('_authority_resource_refusal_prepare_v2(jsonb,integer,integer)','1cf4deb21d1776d53041718e1a2d453150d83b269a8de108d021b736a348d831',true,'v',true,'preserve'),
 ('_authority_resource_registration_authority_final_v2(jsonb,timestamptz)','5369474ff41744e9375e8b91ed623a1fbeab6c8dcd954f563a89dcdbf672b965',true,'i',true,'preserve'),
 ('_authority_resource_registration_authority_wait_v2(jsonb,jsonb,text,jsonb,integer,integer)','8b92777acd79df9e879a5be7bfd2fc0cb9b70c1230f941a55c8e20d8c1c126bb',true,'v',true,'preserve'),
 ('_authority_resource_registration_binding_wait_v2(jsonb,jsonb,integer)','8737eebc8314ab0caf06537329e3d376f94daaaedd424faf11df30c7d41e8fa2',true,'v',true,'preserve'),
 ('_authority_resource_registration_delete_fold_v2(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz)','140ccec2507036d09f2e81db00356442d8fd561a742b6e8752b4dd377be26171',true,'i',true,'preserve'),
 ('_authority_resource_registration_direct_program_v2(jsonb,jsonb,timestamptz)','89e76fe747ba97a46120af7c1548b02835beba9e19618fb03b0add94bf3c434c',true,'i',true,'preserve'),
 ('_authority_resource_registration_direct_sources_v2(jsonb,jsonb)','35a8292b281969ee1003e54336a2acda78e2c592daa4022b1412efd1996a0427',true,'i',true,'preserve'),
 ('_authority_resource_registration_fact_v2(text,text,jsonb)','81397be2c987bdd6787b0cc3fc52692b970c534ab42d126e5f1aafd28484c4c9',true,'i',true,'preserve'),
 ('_authority_resource_registration_intent_certificate_v2(jsonb,jsonb,jsonb,jsonb)','3fde2c87a6c7b8e3aebbd36fef57b37671f46b313af2e3348d9b27b0032015eb',true,'i',true,'preserve'),
 ('_authority_resource_registration_manifest_images_v2(jsonb,jsonb,jsonb)','acecdc1f6a1f2a36d62c82af93ccad6351700ba1bd927d26240c480ebc5b1596',true,'i',true,'preserve'),
 ('_authority_resource_registration_materialize_v2(jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz)','455a6cb564a14038aff88f58f383ed79625016ec2896cf0f2f303b0e734a7964',true,'i',true,'preserve'),
 ('_authority_resource_registration_maximum_v2(jsonb,jsonb,jsonb,jsonb,jsonb)','0d869eee616ea83c8f5c20c179c727022ceecf8ff42cb0a53731aba56d8cb6cc',true,'i',true,'preserve'),
 ('_authority_resource_registration_mirror_images_v2(jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz)','909c304c45925ad0cee62e8ddc462b381778fffd89739e36b99195bea4f3b6f7',true,'i',true,'preserve'),
 ('_authority_resource_registration_model_v2(text)','89ac1f6c923ab033b5551fff2d098099518b2b7c15b3530f15e798ef70cf20e9',true,'i',true,'preserve'),
 ('_authority_resource_registration_pack_v2(jsonb,jsonb,jsonb)','c7df4fd61023a840f764bfd36b29151f718b35aa360fb93c55fbeb7618d50ec7',true,'i',true,'preserve'),
 ('_authority_resource_registration_parent_graph_v2(jsonb,jsonb,text)','e9bcecbff08deea42f1eb0a2356aa88075ff5d526e754cd5514c99028b8b0f96',true,'i',true,'preserve'),
 ('_authority_resource_registration_physical_v2(jsonb,jsonb,jsonb,jsonb,timestamptz)','7c765b761ad28fbde1f64094ef30cf61d70c20b555cb8c5026e172c5eea9d918',true,'i',true,'preserve'),
 ('_authority_resource_registration_pointer_images_v2(text,text,text,text,jsonb,timestamptz,jsonb)','dd37d5f9645e4b380d466079441c945a0e5f95fb44341d75bf4859b09a95e7d8',true,'i',true,'preserve'),
 ('_authority_resource_registration_prepare_v2(jsonb,integer,integer)','c2ab0a869a22e4fec8e5b2735055308a15ba545ef33c21d3f2af9c3f0e2bb773',true,'v',true,'preserve'),
 ('_authority_resource_registration_receipt_images_v2(text,text,text,jsonb,timestamptz,text,jsonb)','4a952ac29b2a28cdaa48f73b0f173a759a4ed455ae43677363284976c960a35c',true,'i',true,'preserve'),
 ('_authority_resource_registration_saved_scopes_v2(jsonb,jsonb,text,text)','d2798409d801254b2a63af2de46033cd560cc6c2bde88193a5d31ffea3daaca3',true,'i',true,'preserve'),
 ('_authority_resource_registration_scope_certificate_v2(jsonb,jsonb,text,text,text,text,jsonb,boolean)','e5bbc391fa00cc3362d203916604507a513a81c7963c24e4d0196ba1277f129d',true,'i',true,'preserve'),
 ('_authority_resource_registration_scope_images_v2(text,text,jsonb,jsonb)','a6fedeea120947165db033862934904916bf4ca57f6e02ca9a64efcd155b55f7',true,'i',true,'preserve'),
 ('_authority_resource_registration_step_operations_v2(jsonb,jsonb,jsonb)','7a6d30976cbbfa09e2f388994476cdab3f99e5b949dda0463829b1c5f0c36df7',true,'i',true,'preserve'),
 ('_authority_resource_registration_store_v2(jsonb)','dc264ddd6cd90f698104551e0be54173d83d5576df7e0d75a1c75ad3133f3221',true,'v',true,'preserve'),
 ('_authority_resource_registration_version_v2(text)','09aa74b25e294d4d6c5c43c107212c81f0d1b32acc43e5a74f0588dbcb7d9690',true,'i',true,'preserve'),
 ('_authority_resource_registration_write_images_v2(jsonb,timestamptz,jsonb,jsonb,timestamptz)','af4c099a81327d849e561861eba96568eab9a5ae27c4dbbc77f32ea5f381cd6c',true,'i',true,'preserve'),
 ('_authority_resource_registration_write_keys_v2(jsonb,jsonb)','b7deaeb5ee01534ffeeaaa6ed468794f039487e293d07cfec08240ddc2db73d3',true,'i',true,'preserve'),
 ('_authority_resource_require_capture_v2(jsonb,integer,text,text,text)','3052c274445598750d6646cbb4bc1308311befc0e2cdb125961633702ac0bd35',true,'i',true,'preserve'),
 ('_authority_resource_required_reread_v2(jsonb,jsonb,jsonb,integer,integer)','4821805cd8b27cce9cddbf1ebc17186aec073d2bbc64860ab7ab888dffae0aa3',true,'v',true,'preserve'),
 ('_authority_resource_row_image_v2(text,jsonb)','f6c7bdc6437dd7e32592f53af7795438fc97164a8ed1d33f7d9522e659548e42',true,'i',true,'preserve'),
 ('_authority_resource_rule_fingerprint_v2(jsonb,boolean)','4dda7544eeae0b21c7d6ba080ce541e68989f6e2f9de72544ff1b23f4dfdb7a5',true,'i',true,'preserve'),
 ('_authority_resource_rule_layout_v2(jsonb,jsonb)','fcf600cf8eaafe1211e0b663bd798dbd025bb9429d06066507dd648256b8013d',true,'i',true,'preserve'),
 ('_authority_resource_rule_witness_v2(jsonb,text,jsonb)','ef7b397fd945ad8df12c6f541a3764b34b2242751289085ba43a908089f17a6a',true,'i',true,'preserve'),
 ('_authority_resource_selector_matches_v2(jsonb,text,text,jsonb)','b925d87aa30d19a06d00e346d26e381721cc63c8eb4deb12f0f1a15b3e49da68',true,'i',true,'preserve'),
 ('_authority_resource_selector_rows_v2(jsonb,integer,integer)','d7da86929ecc720bfd1f617a1c02ae074a487c8280e931a91cba0f008c8060ef',true,'v',true,'preserve'),
 ('_authority_resource_selector_shape_v2(jsonb,integer,integer)','c044631ad4287271aa8540488883ec06983a5abb85f484388a25cba713191a3c',true,'v',true,'preserve'),
 ('_authority_resource_source_wait_v2(jsonb,boolean,integer,integer)','1ce9b16ec596aa1521e295cadb310ea5680c69ba5ea12ee995f186adeb5bd654',true,'v',true,'preserve'),
 ('_authority_resource_special_member_v2(jsonb,jsonb,text,jsonb,jsonb,jsonb)','e47d34def68f6842c3151a02397b689c71ffd98e8d54dc26788f515ea956f783',true,'i',true,'preserve'),
 ('_authority_resource_subject_change_wait_v2(integer,integer)','cc7f8c5748e402e0db8aaf00cec19cd38600ab9744886f4f55ec86d29d803933',true,'v',true,'preserve'),
 ('_authority_resource_target_contains_v2(jsonb,text,text)','5c3e97459a3935ec873831692d25cf522a7ca8447a97fbb376a1be6aa9fd8186',true,'i',true,'preserve'),
 ('_authority_resource_tuple_relations_v2(jsonb,jsonb,text,jsonb,text)','12783ae0cb998e5b67d6fbb72bea4acea1467078509b818a2a2b0c4524d402a8',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_audit_hierarchy_v2(jsonb,jsonb,jsonb,jsonb)','6f8f54188fade71649c640691ff5cabeffcf1512f89d4744e138be4b6f6a00d2',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_certificate_v2(jsonb,jsonb,jsonb,jsonb,jsonb)','023353817aec9d9ab441c2e5bd8f9ba66b6d2164d7d71f2d82f646b025a4e615',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_current_v2(jsonb,jsonb,jsonb)','91cb5cb519e0a34e103fcf84df5ecf2259c656282c55a0fc4c88a5f83cd84101',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_direct_program_v2(jsonb,jsonb,timestamptz)','8e88012c6babe593a7203c818726d8c768e7f907015c731c1cf115aa59195e8b',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_fold_v2(jsonb,jsonb,timestamptz)','981a3753a9d5149fc3ad5996f3b7664989a1a58b66915f9d639b55b769f818be',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_journal_images_v2(text,jsonb,jsonb,jsonb,jsonb,timestamptz)','bd2c3a71cf82e7a55a4d0b3cd271c0114afd4d18bfa5d1196fb8425493c3fd48',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_journal_program_v2(jsonb,jsonb,jsonb,timestamptz)','e6778dd30178f736816a8816a83005179aa0a3c651242c51bf0a9c10207dd5be',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_journal_rows_v2(jsonb,jsonb)','559ccb301f1c99a57f71910e7407a76e93f20393b88ef7f77c08d96f6bd211cf',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_materialize_v2(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','a5dcf1324a5a8daca8e3e80ccd296cb9f737a8a90a65ddc85f5e36269835300b',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_maximum_v2(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb)','15d8361f789a52deaa920abbf46dddfff367d65bc15668f393e2cd93e61b7009',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_mirror_images_v2(jsonb,text)','2cfc03821a5f30ce8e657ca020329a1e54c29c728a125f1a32e6a8b2b4a7c32c',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_object_v2(jsonb,jsonb,text)','d553151e5ff2b50c946bdefb0f5a47c342de88cd97da547afe5b726d8f9b2e3f',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_operation_acl_v2(jsonb,oid,jsonb)','075c20b7bb9f2d06dec73df64186da0b9d4bcc500b99fcbc28ef9b4f21ce7fea',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_operation_maximum_v2(jsonb,jsonb)','79cded719033e41b9a38951033f494bb29e4b48a8c4def81d0126376f333cb45',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_physical_v2(jsonb)','c78c70847fb31b8d1dc082e413a6cc5827f1b79eee9eb067410258408a22221d',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_roots_v2(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb)','d59ef0d706c1f24a98b764ba805604e411d5f54980c64e6d2e8efd1ae3d6a306',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_source_metadata_v2(jsonb,jsonb,jsonb)','67fbae698c0f4362c2d1a7245a8db1073e76ad0ba5aef10cf43fc8f2427e5b40',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_tail_program_v2(jsonb,jsonb,jsonb,jsonb,timestamptz)','93238ccdb1002e80ed0651b7802a3c392c7a3714ca12bfb77053f6fd399dfe9b',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_withdrawal_program_v2(jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','ec2574723c93de9016b0156bb712879eecdafdfa2270f97f8cf4df57c52a4069',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_write_keys_v2(jsonb,jsonb)','ee116834532cc77d78fd300dda8c172da48781107d6b1813027c659001619161',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_binding_images_v2(jsonb,jsonb,jsonb,timestamptz,timestamptz)','787963fad1924ff537cd5dd113e5b0cad7e05abbda3d8b3b3e3ca1b7238e5178',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_binding_v2(jsonb,jsonb,jsonb,jsonb,text,jsonb)','c21e989d6476855358771d8780d9bc5e02f9cd5d46540c08d1690071f129aaf3',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_bindings_v2(jsonb,jsonb,jsonb,text,jsonb)','e8eec4698549dca98cc22b3aebd1f6580d4ffd81241fbf82994c50653b8ac900',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_census_v2(jsonb,jsonb)','d27e53aef5e2f64ed1ad158e3aa31047b3845afb8b80908eca271674a4728c13',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_physical_v2(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','44869037245345da786a82632bb8f22d2a5095769ea5b194cd39ff63933b354d',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_retention_v2(jsonb,text,jsonb,jsonb,jsonb)','50d877065d0b35b3a8b9f13319110f0c736a790c18be146c38ba66fd471ecd81',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_role_images_v2(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','414605ec9f19132a0cb9fb3f89d3524e8547c400ae2bc45083865b53bee2fb68',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_role_projection_v2(jsonb,jsonb,jsonb,jsonb)','89c1b44eb9a74c42c2be80f3f395e05216636481893f47ac85b6696704689ab6',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_role_rules_v2(jsonb,jsonb,text,jsonb)','9491569e7691e17074fe14ef74539351bd21fb7776970eb82a6f79a4aef1ea0b',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_roles_v2(jsonb,jsonb,jsonb,text,jsonb,jsonb,jsonb)','7a8a458214d4d7047ef95b7a7d89d1cf30fb44c2b0e641a9d0eddcb3cd3a70bd',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_rules_v2(jsonb,text,text)','7bf6058618cf10048a6cb7671342c222e6dd24ff4825d6743990dd2a8c50e29c',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_split_v2(jsonb)','27da9c2fbe328e2cd4013f991dc62e7ee75ee1031a5bd5e42dd86bcd1fac7282',true,'i',true,'preserve'),
 ('_authority_resource_without_name_v2(jsonb,text,text,text,boolean,boolean)','d97ead12d3586dac0380d636ddfeb73100ddcf5310211834371babd3f3d0468a',true,'i',true,'preserve'),
 ('authority_binding_epoch_changed()','c75ff7ef8281b75973bd0a6d7fe2a4e3920adc4471a06d52a68613330205efc3',true,'v',true,'preserve'),
 ('authority_binding_epoch_read(text[])','37c8fcd579b297a3c7a749b2889ad95a95561341c63bfa4eb3355284ed583b05',true,'s',true,'preserve'),
 ('authority_binding_epoch_scope(text,jsonb)','ae4b14d1640a4473eb8852512b1722b6439a178b2f1fde5fdc76dcc637e2fb30',true,'s',true,'preserve'),
 ('authority_group_object_scopes(text,text)','ed9f62070e461be31342d7c4e3cfcbbb2e3542f2309b63f9592b80a46bd3cc60',true,'s',true,'preserve'),
 ('authority_protocol_row_account(text,jsonb)','36453c01ccca68634dcf0aac077f00cb17a82cb6fe9bb2406ac633380c4b4a9e',true,'s',true,'preserve'),
 ('resource_journal_project(text,jsonb)','a792cf1d91d0d5b16d01f530109ad7b08559e1bea98632d30fbeadec4bfbdbb7',false,'i',false,'preserve'),
 ('resource_journal_scope(text,jsonb)','22deae6b397c11f7558bd7e10c64400e06ea0f765f5b7f17ba03fe1d00aa1da9',false,'s',false,'preserve')
 ) pinned(signature,digest,definer,volatility,fixed_path,access_mode) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('kaname.'||expected.signature)
   AND p.proowner=owner_oid AND p.prosecdef=expected.definer AND p.provolatile::text=expected.volatility
   AND CASE WHEN expected.fixed_path THEN p.proconfig=ARRAY['search_path=pg_catalog, pg_temp'] ELSE p.proconfig IS NULL END
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=expected.digest) THEN RETURN false;END IF;
  IF expected.access_mode='private' AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   WHERE p.oid=to_regprocedure('kaname.'||expected.signature) AND a.grantee<>owner_oid) THEN RETURN false;END IF;
  IF expected.access_mode='export' AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   WHERE p.oid=to_regprocedure('kaname.'||expected.signature) AND a.grantee<>owner_oid
   AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR NOT EXISTS(
    SELECT 1 FROM pg_catalog.pg_proc e CROSS JOIN LATERAL aclexplode(e.proacl) g
    WHERE e.oid='kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'::regprocedure
     AND g.grantee=a.grantee AND g.privilege_type='EXECUTE'))) THEN RETURN false;END IF;
 END LOOP;
 -- Mirror остаётся единственным AFTER INSERT/UPDATE OF тех же трёх колонок.
 IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname.membership_mirror_from_user()'::regprocedure)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid='kaname.users'::regclass
  AND t.tgname='membership_mirrors_user_row' AND t.tgfoid='kaname.membership_mirror_from_user()'::regprocedure
  AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=21
  AND t.tgconstraint=0 AND NOT t.tgdeferrable AND NOT t.tginitdeferred
  AND t.tgnargs=0 AND octet_length(t.tgargs)=0 AND t.tgqual IS NULL
  AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL
  AND (SELECT array_agg(a.attname::text ORDER BY x.position)
   FROM unnest(t.tgattr) WITH ORDINALITY x(attnum,position)
   JOIN pg_catalog.pg_attribute a ON a.attrelid=t.tgrelid AND a.attnum=x.attnum AND NOT a.attisdropped)
    =ARRAY['account_id','invite_status','invited_by']::text[]) THEN RETURN false;END IF;
 -- Точная схема вызовов: нельзя снять guard, сделать deferred или добавить
 -- второй вызов того же emitter вне скомпилированного eventset.
 FOR expected IN SELECT * FROM (VALUES
 ('accounts','authority_crud_unique','authority_crud_unique_guard_v3()',23,0,'',false,NULL,NULL),
 ('projects','authority_crud_unique','authority_crud_unique_guard_v3()',23,0,'',false,NULL,NULL),
 ('service_accounts','authority_crud_unique','authority_crud_unique_guard_v3()',23,0,'',false,NULL,NULL),
 ('issued_account_ids','authority_crud_unique','authority_crud_unique_guard_v3()',23,0,'',false,NULL,NULL),
 ('project_resource_quotas','authority_crud_unique','authority_crud_unique_guard_v3()',23,0,'',false,NULL,NULL),
 ('identity_admission_windows','authority_crud_unique','authority_crud_unique_guard_v3()',23,0,'',false,NULL,NULL),
 ('resource_journal','authority_crud_sequence','authority_crud_sequence_guard_v3()',23,0,'',false,NULL,NULL),
 ('fga_outbox','authority_crud_sequence','authority_crud_sequence_guard_v3()',23,0,'',false,NULL,NULL),
 ('issued_account_ids','authority_crud_aux_before','_authority_crud_aux_write_v3()',31,0,'',false,NULL,NULL),
 ('issued_account_ids','authority_crud_aux_after','_authority_crud_aux_write_v3()',29,0,'',false,NULL,NULL),
 ('project_resource_quotas','authority_crud_aux_before','_authority_crud_aux_write_v3()',31,0,'',false,NULL,NULL),
 ('project_resource_quotas','authority_crud_aux_after','_authority_crud_aux_write_v3()',29,0,'',false,NULL,NULL),
 ('identity_admission_windows','authority_crud_aux_before','_authority_crud_aux_write_v3()',31,0,'',false,NULL,NULL),
 ('identity_admission_windows','authority_crud_aux_after','_authority_crud_aux_write_v3()',29,0,'',false,NULL,NULL),
 ('role_grant_orphan','authority_crud_aux_before','_authority_crud_aux_write_v3()',31,0,'',false,NULL,NULL),
 ('role_grant_orphan','authority_crud_aux_after','_authority_crud_aux_write_v3()',29,0,'',false,NULL,NULL),
 ('role_selector_prune','authority_crud_aux_before','_authority_crud_aux_write_v3()',31,0,'',false,NULL,NULL),
 ('role_selector_prune','authority_crud_aux_after','_authority_crud_aux_write_v3()',29,0,'',false,NULL,NULL),
 ('issued_account_ids','authority_crud_aux_statement','_authority_crud_aux_statement_v3()',62,0,'',false,NULL,NULL),
 ('project_resource_quotas','authority_crud_aux_statement','_authority_crud_aux_statement_v3()',62,0,'',false,NULL,NULL),
 ('identity_admission_windows','authority_crud_aux_statement','_authority_crud_aux_statement_v3()',62,0,'',false,NULL,NULL),
 ('role_grant_orphan','authority_crud_aux_statement','_authority_crud_aux_statement_v3()',62,0,'',false,NULL,NULL),
 ('role_selector_prune','authority_crud_aux_statement','_authority_crud_aux_statement_v3()',62,0,'',false,NULL,NULL),
 ('resource_journal','authority_crud_aux_statement','_authority_crud_aux_statement_v3()',62,0,'',false,NULL,NULL),
 ('resource_journal','authority_crud_journal_applied','authority_crud_journal_applied_v3()',5,0,'',false,NULL,NULL),
 ('fga_outbox','authority_crud_fga_id_guard','authority_crud_fga_id_guard_v3()',7,0,'',false,NULL,NULL),
 ('fga_outbox','authority_crud_fga_id_applied','authority_crud_fga_id_applied_v3()',5,0,'',false,NULL,NULL),
 ('resource_journal','authority_sequence_program_applied_v3','authority_sequence_program_applied_v3()',5,0,'',false,NULL,NULL),
 ('fga_outbox','authority_sequence_program_applied_v3','authority_sequence_program_applied_v3()',5,0,'',false,NULL,NULL),
 ('accounts','accounts_000_sequence_origin_insert','authority_sequence_origin_v3()',5,0,'',false,NULL,NULL),
 ('accounts','accounts_000_sequence_origin_update','authority_sequence_origin_v3()',17,0,'',true,NULL,NULL),
 ('accounts','accounts_000_sequence_origin_delete','authority_sequence_origin_v3()',11,0,'',false,NULL,NULL),
 ('projects','projects_000_sequence_origin_insert','authority_sequence_origin_v3()',5,0,'',false,NULL,NULL),
 ('projects','projects_000_sequence_origin_update','authority_sequence_origin_v3()',17,0,'',true,NULL,NULL),
 ('projects','projects_000_sequence_origin_delete','authority_sequence_origin_v3()',11,0,'',false,NULL,NULL),
 ('users','users_000_sequence_origin_insert','authority_sequence_origin_v3()',5,0,'',false,NULL,NULL),
 ('users','users_000_sequence_origin_update','authority_sequence_origin_v3()',17,0,'',true,NULL,NULL),
 ('users','users_000_sequence_origin_delete','authority_sequence_origin_v3()',11,0,'',false,NULL,NULL),
 ('groups','groups_000_sequence_origin_insert','authority_sequence_origin_v3()',5,0,'',false,NULL,NULL),
 ('groups','groups_000_sequence_origin_update','authority_sequence_origin_v3()',17,0,'',true,NULL,NULL),
 ('groups','groups_000_sequence_origin_delete','authority_sequence_origin_v3()',11,0,'',false,NULL,NULL),
 ('service_accounts','service_accounts_000_sequence_origin_insert','authority_sequence_origin_v3()',5,0,'',false,NULL,NULL),
 ('service_accounts','service_accounts_000_sequence_origin_update','authority_sequence_origin_v3()',17,0,'',true,NULL,NULL),
 ('service_accounts','service_accounts_000_sequence_origin_delete','authority_sequence_origin_v3()',11,0,'',false,NULL,NULL),
 ('roles','roles_000_sequence_origin_insert','authority_sequence_origin_v3()',5,0,'',false,NULL,NULL),
 ('roles','roles_000_sequence_origin_update','authority_sequence_origin_v3()',17,0,'',true,NULL,NULL),
 ('roles','roles_000_sequence_origin_delete','authority_sequence_origin_v3()',11,0,'',false,NULL,NULL),
 ('access_bindings','access_bindings_000_sequence_origin_insert','authority_sequence_origin_v3()',5,0,'',false,NULL,NULL),
 ('access_bindings','access_bindings_000_sequence_origin_update','authority_sequence_origin_v3()',17,0,'',true,NULL,NULL),
 ('access_bindings','access_bindings_000_sequence_origin_delete','authority_sequence_origin_v3()',11,0,'',false,NULL,NULL),
 ('group_members','group_members_000_sequence_origin','authority_sequence_origin_v3()',13,0,'',false,NULL,NULL),
 ('memberships','memberships_000_sequence_origin','authority_sequence_origin_v3()',13,0,'',false,NULL,NULL),
 ('access_binding_subjects','access_binding_subjects_000_sequence_origin','authority_sequence_origin_v3()',13,0,'',false,NULL,NULL),
 ('accounts','accounts_resource_journal_insert_trg','resource_journal_emit()',5,1,'6163636f756e7400',false,NULL,NULL),
 ('accounts','accounts_resource_journal_update_trg','resource_journal_emit()',17,1,'6163636f756e7400',true,NULL,NULL),
 ('accounts','accounts_resource_journal_delete_trg','resource_journal_emit()',11,1,'6163636f756e7400',false,NULL,NULL),
 ('projects','projects_resource_journal_insert_trg','resource_journal_emit()',5,1,'70726f6a65637400',false,NULL,NULL),
 ('projects','projects_resource_journal_update_trg','resource_journal_emit()',17,1,'70726f6a65637400',true,NULL,NULL),
 ('projects','projects_resource_journal_delete_trg','resource_journal_emit()',11,1,'70726f6a65637400',false,NULL,NULL),
 ('users','users_resource_journal_insert_trg','resource_journal_emit()',5,1,'69616d5f7573657200',false,NULL,NULL),
 ('users','users_resource_journal_update_trg','resource_journal_emit()',17,1,'69616d5f7573657200',true,NULL,NULL),
 ('users','users_resource_journal_delete_trg','resource_journal_emit()',11,1,'69616d5f7573657200',false,NULL,NULL),
 ('groups','groups_resource_journal_insert_trg','resource_journal_emit()',5,1,'69616d5f67726f757000',false,NULL,NULL),
 ('groups','groups_resource_journal_update_trg','resource_journal_emit()',17,1,'69616d5f67726f757000',true,NULL,NULL),
 ('groups','groups_resource_journal_delete_trg','resource_journal_emit()',11,1,'69616d5f67726f757000',false,NULL,NULL),
 ('service_accounts','service_accounts_resource_journal_insert_trg','resource_journal_emit()',5,1,'69616d5f736572766963655f6163636f756e7400',false,NULL,NULL),
 ('service_accounts','service_accounts_resource_journal_update_trg','resource_journal_emit()',17,1,'69616d5f736572766963655f6163636f756e7400',true,NULL,NULL),
 ('service_accounts','service_accounts_resource_journal_delete_trg','resource_journal_emit()',11,1,'69616d5f736572766963655f6163636f756e7400',false,NULL,NULL),
 ('roles','roles_resource_journal_insert_trg','resource_journal_emit()',5,1,'69616d5f726f6c6500',false,NULL,NULL),
 ('roles','roles_resource_journal_update_trg','resource_journal_emit()',17,1,'69616d5f726f6c6500',true,NULL,NULL),
 ('roles','roles_resource_journal_delete_trg','resource_journal_emit()',11,1,'69616d5f726f6c6500',false,NULL,NULL),
 ('access_bindings','access_bindings_resource_journal_insert_trg','resource_journal_emit()',5,1,'69616d5f6163636573735f62696e64696e6700',false,NULL,NULL),
 ('access_bindings','access_bindings_resource_journal_update_trg','resource_journal_emit()',17,1,'69616d5f6163636573735f62696e64696e6700',true,NULL,NULL),
 ('access_bindings','access_bindings_resource_journal_delete_trg','resource_journal_emit()',11,1,'69616d5f6163636573735f62696e64696e6700',false,NULL,NULL),
 ('group_members','group_members_resource_journal_trg','resource_journal_emit_member()',13,3,'69616d5f67726f75700067726f75705f69640067726f75707300',false,NULL,NULL),
 ('memberships','memberships_resource_journal_trg','resource_journal_emit_member()',13,3,'69616d5f7573657200757365725f696400757365727300',false,NULL,NULL),
 ('access_binding_subjects','access_binding_subjects_resource_journal_trg','resource_journal_emit_member()',13,3,'69616d5f6163636573735f62696e64696e670062696e64696e675f6964006163636573735f62696e64696e677300',false,NULL,NULL),
 ('accounts','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('accounts','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('accounts','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('accounts','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('projects','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('projects','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('projects','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('projects','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('roles','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('roles','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('roles','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('roles','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('groups','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('groups','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('groups','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('groups','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('users','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('users','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('users','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('users','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('service_accounts','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('service_accounts','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('service_accounts','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('service_accounts','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('memberships','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('memberships','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('memberships','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('memberships','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('access_bindings','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('access_bindings','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('access_bindings','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('access_bindings','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('access_binding_subjects','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('access_binding_subjects','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('access_binding_subjects','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('access_binding_subjects','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('access_binding_target_members','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('access_binding_target_members','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('access_binding_target_members','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('access_binding_target_members','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('access_binding_emitted_tuples','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('access_binding_emitted_tuples','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('access_binding_emitted_tuples','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('access_binding_emitted_tuples','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('role_rule_selectors','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('role_rule_selectors','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('role_rule_selectors','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('role_rule_selectors','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('role_selector_verbs_pending','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('role_selector_verbs_pending','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('role_selector_verbs_pending','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('role_selector_verbs_pending','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('role_verb','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('role_verb','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('role_verb','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('role_verb','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('role_rule_ref','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('role_rule_ref','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('role_rule_ref','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('role_rule_ref','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('role_create_binding_rule','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('role_create_binding_rule','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('role_create_binding_rule','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('role_create_binding_rule','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('role_bind_role_rule','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('role_bind_role_rule','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('role_bind_role_rule','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('role_bind_role_rule','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('catalog_module','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('catalog_module','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('catalog_module','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('catalog_module','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('catalog_resource','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('catalog_resource','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('catalog_resource','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('catalog_resource','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('catalog_verb','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('catalog_verb','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('catalog_verb','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('catalog_verb','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('resource_mirror','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('resource_mirror','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('resource_mirror','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('resource_mirror','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('resource_parent_edge','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('resource_parent_edge','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('resource_parent_edge','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('resource_parent_edge','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('grant_delegations','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('grant_delegations','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('grant_delegations','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('grant_delegations','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL)
 ) graph(table_name,trigger_name,signature,trigger_type,nargs,argument_hex,has_qual,old_table,new_table) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=to_regclass('kaname.'||expected.table_name)
   AND c.relowner=owner_oid AND c.relkind='r' AND c.relpersistence='p') THEN RETURN false;END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=to_regclass('kaname.'||expected.table_name)
   AND t.tgname=expected.trigger_name AND t.tgfoid=to_regprocedure('kaname.'||expected.signature)
   AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=expected.trigger_type
   AND t.tgconstraint=0 AND NOT t.tgdeferrable AND NOT t.tginitdeferred
   AND t.tgnargs=expected.nargs AND encode(t.tgargs,'hex')=expected.argument_hex AND t.tgattr=''::int2vector
   AND t.tgoldtable::text IS NOT DISTINCT FROM expected.old_table AND t.tgnewtable::text IS NOT DISTINCT FROM expected.new_table
   -- Trigger qual имеет две range-table записи OLD/NEW; pg_get_expr для него
   -- неприменим. Сравнивается вся WHEN-clause trigger-aware deparser, не подстрока.
   AND CASE WHEN expected.has_qual THEN t.tgqual IS NOT NULL
    AND substring(pg_get_triggerdef(t.oid,false) FROM ' WHEN (.*) EXECUTE FUNCTION ')='((old.* IS DISTINCT FROM new.*))'
    ELSE t.tgqual IS NULL END)
  THEN RETURN false;END IF;
 END LOOP;
 IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname._authority_crud_aux_statement_v3()'::regprocedure)<>6 THEN RETURN false;END IF;
 IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname._authority_crud_aux_write_v3()'::regprocedure)<>10 THEN RETURN false;END IF;
 IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname.authority_binding_epoch_changed()'::regprocedure)<>92 THEN RETURN false;END IF;
 IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname.authority_crud_fga_id_applied_v3()'::regprocedure)<>1 THEN RETURN false;END IF;
 IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname.authority_crud_fga_id_guard_v3()'::regprocedure)<>1 THEN RETURN false;END IF;
 IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname.authority_crud_journal_applied_v3()'::regprocedure)<>1 THEN RETURN false;END IF;
 IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname.authority_crud_sequence_guard_v3()'::regprocedure)<>2 THEN RETURN false;END IF;
 IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname.authority_crud_unique_guard_v3()'::regprocedure)<>6 THEN RETURN false;END IF;
 IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname.authority_sequence_origin_v3()'::regprocedure)<>24 THEN RETURN false;END IF;
 IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname.authority_sequence_program_applied_v3()'::regprocedure)<>2 THEN RETURN false;END IF;
 IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname.resource_journal_emit()'::regprocedure)<>21 THEN RETURN false;END IF;
 IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname.resource_journal_emit_member()'::regprocedure)<>3 THEN RETURN false;END IF;
 -- Defaults принадлежат ровно тем же owned sequences; свободный nextval
 -- вместо wrapper вновь открыл бы after-clock unique arbitration.
 FOR expected IN SELECT * FROM (VALUES
  ('resource_journal','sequence_no','authority_resource_journal_id_v3()','resource_journal_sequence_no_seq'),
  ('fga_outbox','id','authority_fga_outbox_id_v3()','fga_outbox_id_seq')
 ) d(table_name,column_name,default_name,sequence_name) LOOP
  IF pg_get_serial_sequence('kaname.'||expected.table_name,expected.column_name)::regclass::oid
   IS DISTINCT FROM to_regclass('kaname.'||expected.sequence_name)
  OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
   WHERE a.attrelid=to_regclass('kaname.'||expected.table_name) AND a.attname=expected.column_name AND NOT a.attisdropped
   AND pg_get_expr(d.adbin,d.adrelid)='kaname.'||expected.default_name) THEN RETURN false;END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid='kaname._authority_sequence_probe_v3()'::regprocedure
  AND p.pronargs=0 AND p.proretset AND p.prorettype='record'::regtype
  AND p.proargnames=ARRAY['proof','header']::text[] AND p.proargmodes=ARRAY['t','t']::"char"[]
  AND p.proallargtypes=ARRAY['jsonb'::regtype::oid,'jsonb'::regtype::oid]) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid='kaname._authority_protocol_snapshot_v3()'::regprocedure
  AND p.pronargs=0 AND p.proretset AND p.prorettype='record'::regtype
  AND p.proargnames=ARRAY['proof','compatibility_shared','compatibility_exclusive','population_oid',
   'population_shared','population_row_exclusive','population_extra_shared','population_extra_row_exclusive']::text[]
  AND p.proargmodes=ARRAY['t','t','t','t','t','t','t','t']::"char"[]
  AND p.proallargtypes=ARRAY['jsonb'::regtype::oid,'boolean'::regtype::oid,'boolean'::regtype::oid,'oid'::regtype::oid,
   'boolean'::regtype::oid,'boolean'::regtype::oid,'boolean'::regtype::oid,'boolean'::regtype::oid]) THEN RETURN false;END IF;
 RETURN true;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_full_contract_storage_v3() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE expected record; owner_oid oid; target text;
BEGIN
 SELECT relowner INTO owner_oid FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass;
 IF owner_oid IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=to_regclass('kaname.authority_writer_contract') AND relowner=owner_oid AND relkind='r' AND relpersistence='p')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
  WHERE c.oid=to_regclass('kaname.authority_writer_contract') AND a.grantee<>owner_oid) THEN RETURN false; END IF;
 FOR target IN SELECT unnest(kaname.authority_protocol_tables()) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=to_regclass('kaname.'||target)
   AND t.tgname='authority_protocol_statement' AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=62
   AND t.tgfoid='kaname.authority_protocol_statement_guard()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=to_regclass('kaname.'||target)
   AND t.tgname='authority_protocol_row' AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=31
   AND t.tgfoid='kaname.authority_protocol_row_guard()'::regprocedure) THEN RETURN false; END IF;
 END LOOP;
 -- Catalog invalidation is part of the full writer ABI: no early row close
 -- and no missed commit close. Check both pg_trigger and its constraint row.
 IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname._authority_protocol_catalog_changed_v3()'::regprocedure)<>6
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgfoid='kaname.authority_protocol_catalog_changed()'::regprocedure) THEN RETURN false; END IF;
 FOR target IN SELECT unnest(ARRAY['catalog_module','catalog_resource','catalog_verb']) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=to_regclass('kaname.'||target) AND c.relowner=owner_oid AND c.relkind='r' AND c.relpersistence='p') THEN RETURN false; END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_constraint c ON c.oid=t.tgconstraint
   WHERE t.tgrelid=to_regclass('kaname.'||target) AND t.tgname='authority_catalog_changed'
   AND t.tgfoid='kaname._authority_protocol_catalog_changed_v3()'::regprocedure
   AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=29
   AND t.tgdeferrable AND t.tginitdeferred AND t.tgnargs=0 AND t.tgqual IS NULL AND t.tgattr=''::int2vector
   AND c.contype='t' AND c.conname='authority_catalog_changed' AND c.conrelid=t.tgrelid AND c.condeferrable AND c.condeferred)
  OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t
   WHERE t.tgrelid=to_regclass('kaname.'||target) AND t.tgname='authority_catalog_truncated'
   AND t.tgfoid='kaname._authority_protocol_catalog_changed_v3()'::regprocedure
   AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=32 AND t.tgconstraint=0
   AND NOT t.tgdeferrable AND NOT t.tginitdeferred AND t.tgnargs=0 AND t.tgqual IS NULL)
  THEN RETURN false; END IF;
 END LOOP;
 -- Публичен только void-вход. PUBLIC, grant option и посторонний executor
 -- не являются частью approved runtime profile.
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.oid='kaname.authority_role_prelock_admit_v3()'::regprocedure
  AND a.grantee<>owner_oid AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE'
   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc e
    CROSS JOIN LATERAL aclexplode(coalesce(e.proacl,acldefault('f',e.proowner))) g
    WHERE e.oid='kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'::regprocedure
    AND g.grantee=a.grantee AND g.privilege_type='EXECUTE')))
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname.authority_role_prelock_admit_v3()'::regprocedure
  AND p.prorettype='void'::regtype AND p.provolatile='v'
  AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']) THEN RETURN false; END IF;
 -- Общий cutoff backstop принадлежит владельцу и действует на все INSERT/UPDATE.
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid='kaname.minted_token_revocations'::regclass
  AND relowner=owner_oid AND relkind='r' AND relpersistence='p')
 OR (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname._authority_minted_cutoff_order_v3()'::regprocedure)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid='kaname.minted_token_revocations'::regclass
  AND tgname='authority_minted_cutoff_order_v3' AND tgfoid='kaname._authority_minted_cutoff_order_v3()'::regprocedure
  AND tgenabled='O' AND NOT tgisinternal AND tgtype::integer=23 AND tgnargs=0 AND tgqual IS NULL
  AND tgattr=''::int2vector AND tgconstraint=0 AND NOT tgdeferrable AND NOT tginitdeferred)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.oid='kaname.authority_sa_state_preflight_v3(text,boolean,text)'::regprocedure AND a.grantee<>owner_oid
  AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR NOT EXISTS(
   SELECT 1 FROM pg_catalog.pg_proc e CROSS JOIN LATERAL aclexplode(e.proacl) g
   WHERE e.oid='kaname.authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)'::regprocedure
   AND g.grantee=a.grantee AND g.privilege_type='EXECUTE'))) THEN RETURN false; END IF;
 -- Публичен только void-вход. PUBLIC, grant option и посторонний executor
 -- не являются частью approved runtime profile.
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.oid='kaname.authority_parent_prelock_admit_v3()'::regprocedure
  AND a.grantee<>owner_oid AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE'
   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc e
    CROSS JOIN LATERAL aclexplode(coalesce(e.proacl,acldefault('f',e.proowner))) g
    WHERE e.oid='kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'::regprocedure
    AND g.grantee=a.grantee AND g.privilege_type='EXECUTE')))
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname.authority_parent_prelock_admit_v3()'::regprocedure
  AND p.prorettype='void'::regtype AND p.provolatile='v'
  AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']) THEN RETURN false; END IF;
 FOR expected IN SELECT * FROM (VALUES
 ('_authority_crud_storage_v3()','731830ada6d11ff80ad42efa8ab9f1db1ff3cf90ed96620fad82d58fb2b6f122',true),
 ('authority_parent_prelock_admit_v3()','0a5d8d81822501af40183c78d52e8897d3bf8583e8b888589a64951a88139247',true),
 ('_authority_minted_cutoff_key_v3(text)','e070405bfea920fb884831cd02890bd90810a65f4d617a828b1af9ea48542623',true),
 ('_authority_minted_cutoff_order_v3()','d911640bce1f00a365213aa03845461e4d6f479ca564e40745b810ad2976dd29',true),
 ('authority_sa_state_preflight_v3(text,boolean,text)','980a05e9e1dc6973b93ba6694ea376a70efaa22a4639e5b762b425b81dbad3f7',true),
 ('authority_role_prelock_admit_v3()','0a5d8d81822501af40183c78d52e8897d3bf8583e8b888589a64951a88139247',true),
 ('_authority_protocol_catalog_changed_v3()','974332f1dc2c6f42d12d35c49c89c201ac5deecf153f46070746ca0fcef6fbbb',true),
 ('authority_metadata_preflight_v3(text,text,boolean,text)','ea89b06dc47ce62579a99026522c1d8dd4c0edc585922c71ca77c9ea11b07ed3',true),
 ('_authority_protocol_enter_contract_v3(text,text[],jsonb,text,text,text,text,integer,text,integer)','1eae08ffff7b4eb936b224dfa08ed3e49679e968033a8e823e0bd3ef6d9786cf',true),
 ('_authority_consumer_enter_contract_v3(text,text[],jsonb,text,text,text,text,text,text,jsonb,integer)','7109bc396aeecee56a015a868826ebcf88bc15a050fceacf033b73971ff50aca',true),
 ('_authority_protocol_enter_v1_body(text,text[],jsonb,text,text,text,text,integer,text)','e71e29754a20d3a18054206600cf26cc6c234f26e798a41d9430177f612d68e4',true),
 ('_authority_protocol_enter_v2(text,text[],jsonb,text,text,text,text,text,text,jsonb)','e4a1ca86b280c64e7c9b5a54bbfb1e4152f59732f40c7f0748a5bb1a86fb77b1',true),
 ('_authority_protocol_attestation_v1_body()','2c6a618c91d3b7fff8a5e23734d8d7815d6c38cb9b82adacd2e472202584fc54',true),
 ('authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)','86ecf97ccb3cd5599f434955609fb3f1335dd82231f881deb510638981c8ec7a',true),
 ('authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)','33c57c5d0b23128b4fa5e694f4863073e7b6bcce4789c3cd98953285a991f1ea',true),
 ('authority_resource_enter_v3(text,text[],jsonb,text,text,text)','8e54f4da31fab3d4706a58039ea84de5ee88c8c258f92f73c65b7e098aebcc2d',true),
 ('authority_resource_source_enter_v3(text,text[],jsonb,text,text,text)','26f28ff899f445a4b2ca54c2d4ea4ac285fb0bf928082475fc862b1d6bddbd6a',true),
 ('authority_installation_enter_v3(text,text,text,text)','c9d988aa2dfb5851a95037d88ab9847da36ec8154507487bc962cc1b3c1f5b44',true),
 ('authority_full_contract_validate_v3(text,text,text)','25bfc4bd59d30c59e9246889a4279e1326b0ecbb5940b220fd52490a8777d1ea',true),
 ('authority_staged_contract_validate_v3()','0438c79b89809642700ab1d12a3dee84f8a0432c3b33589d47d16e8d9ce885b8',true),
 ('authority_protocol_stage_full_v3(text,bytea,text,text,text)','1f7a9c17af7a4c3ec041405fa9f0dddc69cdf3fa666ba72db47247cde8447037',false),
 ('authority_protocol_activate_full_v3(text,text,text)','646328a2433e1d31d17a9c178ac3ab59a5a65d8252accf5295a20d22705d31cf',false),
 ('authority_protocol_attestation()','b14df1dbc506b990b23e320ae5be6bdabce9dbf993af99dae70e5e337de681e2',true),
 ('authority_protocol_statement_guard()','457d0003223d4ad53047310a311f677f94852a6aefd39523d38398b075613da8',true),
 ('authority_protocol_row_guard()','12e0aaa5fff5aadd930c78d09bc660438ad1000a36c978a594964b1532a30652',true),
 ('_authority_protocol_stage_generation1(text,bytea,text,text,text)','7ffb942af742bff4b556f07b00d9d8f75fefba3aa1f00445073140b5c8072bde',false),
 ('_authority_protocol_activate_generation1(text,text,text)','00d97c37e2ab533c232e4cffb975e8d71c3eefa98228e0f39d90249526bf041c',false),
 ('authority_protocol_drain()','f0e36bb29e96ba0417e9143821391b9df518541a017dcd9b171c037e167bc500',false),
 ('authority_protocol_require_drain()','61686507d75a6352d1f0fd97c9e3886c5c361af00778bdf3513693ee2dd6468b',false)
 ) AS pinned(signature,digest,definer) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('kaname.'||expected.signature)
   AND p.proowner=owner_oid AND p.prosecdef=expected.definer
   AND p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=expected.digest) THEN RETURN false; END IF;
  IF left(expected.signature,1)='_' AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
   WHERE p.oid=to_regprocedure('kaname.'||expected.signature) AND a.grantee<>owner_oid) THEN RETURN false; END IF;
 END LOOP;
 RETURN kaname._authority_crud_storage_v3();
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_grant_runtime(p_runtime regrole) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE signature text; runtime_name text;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 PERFORM kaname._authority_protocol_grant_runtime_generation1(p_runtime);
 SELECT rolname INTO STRICT runtime_name FROM pg_catalog.pg_roles WHERE oid=p_runtime;
 FOREACH signature IN ARRAY ARRAY[
  'authority_resource_crud_capture_v3(jsonb,integer,integer)',
  'authority_resource_crud_body_values_v3()',
  'authority_resource_crud_step_v3(text,jsonb)',
  'authority_resource_crud_lock_held_v3(text)',
  'authority_resource_crud_journal_value_v3(jsonb,jsonb)',
  'authority_binding_sequence_prepare_v3(text,jsonb)',
  'authority_binding_sequence_finalize_v3()',
  'authority_binding_insert_stamp_v3(text)',
  'authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)',
  'authority_binding_stage_sequence_prepare_v3(text,text[],jsonb,integer,integer)',
  'authority_binding_stage_sequence_finalize_v3(text)',
  'authority_binding_withdrawal_sequence_prepare_v3(text,text,text,integer,integer)',
  'authority_binding_withdrawal_sequence_finalize_v3()',
  'authority_cluster_admin_preflight_v4(text,text,text)',
  'authority_resource_journal_id_v3()',
  'authority_fga_outbox_id_v3()',
  'authority_prepared_journal_value_v3(jsonb,jsonb)',
  'authority_role_sequence_prepare_v3(jsonb,integer,integer)',
  'authority_role_sequence_finalize_v3()',
  'authority_role_sequence_stamp_v3(jsonb)',
  'authority_metadata_preflight_v4(text,text,boolean,text,jsonb)',
  'authority_sa_state_preflight_v4(text,boolean,text)',
  'authority_scalar_sequence_finalize_v3()',
  'authority_crud_storage_v3()',

  'authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)',
  'authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)',
  'authority_resource_enter_v3(text,text[],jsonb,text,text,text)',
  'authority_resource_source_enter_v3(text,text[],jsonb,text,text,text)',
  'authority_installation_enter_v3(text,text,text,text)',
  'authority_full_contract_validate_v3(text,text,text)',
  'authority_staged_contract_validate_v3()',
  'authority_metadata_preflight_v3(text,text,boolean,text)',
  'authority_role_prelock_admit_v3()',
  'authority_parent_prelock_admit_v3()',
  'authority_sa_state_preflight_v3(text,boolean,text)'] LOOP
  EXECUTE format('GRANT EXECUTE ON FUNCTION kaname.%s TO %I',signature,runtime_name);
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$ DECLARE signature text;r record;BEGIN
 FOREACH signature IN ARRAY ARRAY['_authority_protocol_snapshot_v3()','_authority_sequence_probe_v3()','_authority_sequence_shape_v3()','_authority_sequence_publish_v3(jsonb)','_authority_sequence_header_v3()','_authority_resource_before_write_v3(jsonb,text,text,jsonb,jsonb)','_authority_crud_anchor_capture_v3(jsonb,integer,integer)','_authority_crud_authority_graph_v3(jsonb,jsonb,integer,integer)','_authority_crud_aux_capture_v3(jsonb,jsonb,integer,integer)','_authority_crud_aux_write_v3()','_authority_crud_aux_images_v3(jsonb,jsonb,jsonb,timestamptz)','_authority_crud_aux_statement_v3()','authority_resource_crud_capture_v3(jsonb,integer,integer)','_authority_crud_merge_tables_v3(jsonb,jsonb)','_authority_crud_capture_v3(jsonb,integer,integer)','_authority_crud_cascade_capture_v3(jsonb,integer,integer)','authority_resource_crud_body_values_v3()','_authority_crud_step_complete_v3(jsonb,integer)','authority_resource_crud_step_v3(text,jsonb)','authority_resource_crud_lock_held_v3(text)','_authority_crud_require_completion_v3(jsonb)','_authority_crud_command_v3(text,jsonb)','_authority_crud_structural_v3(text,text,text,text)','_authority_crud_command_plan_v3(jsonb,jsonb)','_authority_crud_image_v3(integer,text,text,jsonb,jsonb,boolean)','_authority_crud_domain_images_v3(jsonb,jsonb,jsonb,timestamptz)','_authority_crud_intent_v3(jsonb)','_authority_crud_manifest_domain_v3(jsonb)','_authority_crud_fga_rows_v3(jsonb,text,jsonb,integer,timestamptz)','authority_crud_fga_id_guard_v3()','authority_crud_fga_id_applied_v3()','_authority_crud_fold_capture_v3(jsonb,integer,integer)','_authority_crud_fold_images_v3(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','_authority_crud_graph_index_v3(jsonb,jsonb,jsonb)','_authority_crud_journal_capture_v3(jsonb,jsonb,integer,integer)','authority_resource_crud_journal_value_v3(jsonb,jsonb)','authority_crud_journal_applied_v3()','_authority_crud_journal_plan_v3(jsonb,jsonb,jsonb)','_authority_crud_journal_rows_v3(jsonb,jsonb,timestamptz)','_authority_crud_unique_key_v3(text,jsonb)','authority_crud_unique_guard_v3()','_authority_crud_sequence_wait_v3(text,integer,integer)','authority_crud_sequence_guard_v3()','_authority_crud_key_maximum_v3(jsonb,jsonb,jsonb,jsonb,timestamptz)','_authority_crud_lock_rows_v3(jsonb)','_authority_crud_lock_plan_v3(jsonb,jsonb,jsonb,timestamptz)','_authority_crud_manifest_images_v3(jsonb,jsonb,jsonb,jsonb)','_authority_resource_crud_materialize_v3(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','_authority_crud_maximum_v3(jsonb,jsonb)','_authority_crud_pack_v3(jsonb,jsonb,jsonb)','_authority_crud_physical_v3(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','_authority_resource_crud_prepare_v3(jsonb,integer,integer)','_authority_crud_relation_wait_v3(jsonb,jsonb,jsonb,integer)','_authority_crud_reserve_v3(jsonb,jsonb,jsonb,integer,integer)','_authority_crud_scope_capture_v3(jsonb,integer,integer)','_authority_resource_crud_store_v3(jsonb)','_authority_crud_tuple_wait_v3(text,jsonb,boolean,integer,integer)','_authority_crud_unique_wait_v3(text,jsonb,integer,integer)','_authority_crud_json_keys_v3(jsonb)','_authority_crud_write_metadata_v3(jsonb,jsonb,jsonb)','_authority_binding_scope_tier_v3(text,jsonb,jsonb)','_authority_binding_journal_v3(text,text,jsonb,jsonb,jsonb,integer)','authority_binding_sequence_prepare_v3(text,jsonb)','authority_binding_sequence_finalize_v3()','authority_binding_insert_stamp_v3(text)','authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)','_authority_binding_stage_snapshot_v3()','authority_binding_stage_sequence_prepare_v3(text,text[],jsonb,integer,integer)','authority_binding_stage_sequence_finalize_v3(text)','_authority_binding_stage_source_v3(jsonb,oid,integer)','_authority_binding_stage_coordinates_v3(jsonb,text[],boolean,oid,integer,integer)','authority_binding_withdrawal_sequence_prepare_v3(text,text,text,integer,integer)','authority_binding_withdrawal_sequence_finalize_v3()','authority_cluster_admin_preflight_v4(text,text,text)','_authority_metadata_preflight_body_v4(text,text,boolean,text)','_authority_sequence_freeze_v3(jsonb)','_authority_sequence_bind_v3(jsonb,timestamptz)','_authority_sequence_default_v3(text)','authority_resource_journal_id_v3()','authority_fga_outbox_id_v3()','authority_sequence_program_applied_v3()','authority_sequence_program_completion_v3()','_authority_sequence_expect_v3(text)','_authority_sequence_expected_v3()','authority_sequence_expectation_complete_v3()','authority_sequence_origin_v3()','authority_prepared_journal_value_v3(jsonb,jsonb)','_authority_sequence_excluded_v3(oid)','_authority_sequence_store_v3()','_authority_sequence_reserve_v3(text,jsonb,integer)','_authority_sequence_select_v3(integer[],timestamptz)','_authority_sequence_claim_v3(text,jsonb,jsonb)','_authority_sequence_applied_v3(text,bigint,jsonb)','_authority_sequence_complete_v3()','_authority_resource_object_sequence_prepare_v3(jsonb,integer)','_authority_resource_object_sequence_final_v3(jsonb,timestamptz)','_authority_resource_registration_sequence_prepare_v3(jsonb,integer,integer)','_authority_resource_registration_sequence_final_v3(jsonb,timestamptz)','authority_role_sequence_prepare_v3(jsonb,integer,integer)','authority_role_sequence_finalize_v3()','authority_role_sequence_stamp_v3(jsonb)','_authority_sa_state_preflight_body_v4(text,boolean,text)','_authority_scalar_journal_v3(text,text,jsonb,jsonb)','authority_metadata_preflight_v4(text,text,boolean,text,jsonb)','authority_sa_state_preflight_v4(text,boolean,text)','authority_scalar_sequence_finalize_v3()','authority_crud_storage_v3()','_authority_crud_storage_v3()'] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM PUBLIC',signature);
  FOR r IN SELECT DISTINCT u.rolname FROM pg_catalog.pg_proc f CROSS JOIN LATERAL aclexplode(f.proacl) a JOIN pg_catalog.pg_roles u ON u.oid=a.grantee WHERE f.oid=to_regprocedure('kaname.'||signature) AND a.grantee<>f.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM %I',signature,r.rolname);
  END LOOP;
 END LOOP;
 FOR r IN SELECT DISTINCT u.rolname FROM pg_catalog.pg_proc f CROSS JOIN LATERAL aclexplode(f.proacl) a JOIN pg_catalog.pg_roles u ON u.oid=a.grantee WHERE f.oid='kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'::regprocedure AND a.grantee<>f.proowner AND a.privilege_type='EXECUTE' LOOP
  FOREACH signature IN ARRAY ARRAY['authority_resource_crud_capture_v3(jsonb,integer,integer)','authority_resource_crud_body_values_v3()','authority_resource_crud_step_v3(text,jsonb)','authority_resource_crud_lock_held_v3(text)','authority_resource_crud_journal_value_v3(jsonb,jsonb)','authority_binding_sequence_prepare_v3(text,jsonb)','authority_binding_sequence_finalize_v3()','authority_binding_insert_stamp_v3(text)','authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)','authority_binding_stage_sequence_prepare_v3(text,text[],jsonb,integer,integer)','authority_binding_stage_sequence_finalize_v3(text)','authority_binding_withdrawal_sequence_prepare_v3(text,text,text,integer,integer)','authority_binding_withdrawal_sequence_finalize_v3()','authority_cluster_admin_preflight_v4(text,text,text)','authority_resource_journal_id_v3()','authority_fga_outbox_id_v3()','authority_prepared_journal_value_v3(jsonb,jsonb)','authority_role_sequence_prepare_v3(jsonb,integer,integer)','authority_role_sequence_finalize_v3()','authority_role_sequence_stamp_v3(jsonb)','authority_metadata_preflight_v4(text,text,boolean,text,jsonb)','authority_sa_state_preflight_v4(text,boolean,text)','authority_scalar_sequence_finalize_v3()','authority_crud_storage_v3()'] LOOP
   EXECUTE format('GRANT EXECUTE ON FUNCTION kaname.%s TO %I',signature,r.rolname);
  END LOOP;
 END LOOP;
END $$;
-- +goose StatementEnd

CREATE TRIGGER authority_crud_unique BEFORE INSERT OR UPDATE ON kaname.accounts FOR EACH ROW EXECUTE FUNCTION kaname.authority_crud_unique_guard_v3();
CREATE TRIGGER authority_crud_unique BEFORE INSERT OR UPDATE ON kaname.projects FOR EACH ROW EXECUTE FUNCTION kaname.authority_crud_unique_guard_v3();
CREATE TRIGGER authority_crud_unique BEFORE INSERT OR UPDATE ON kaname.service_accounts FOR EACH ROW EXECUTE FUNCTION kaname.authority_crud_unique_guard_v3();
CREATE TRIGGER authority_crud_unique BEFORE INSERT OR UPDATE ON kaname.issued_account_ids FOR EACH ROW EXECUTE FUNCTION kaname.authority_crud_unique_guard_v3();
CREATE TRIGGER authority_crud_unique BEFORE INSERT OR UPDATE ON kaname.project_resource_quotas FOR EACH ROW EXECUTE FUNCTION kaname.authority_crud_unique_guard_v3();
CREATE TRIGGER authority_crud_unique BEFORE INSERT OR UPDATE ON kaname.identity_admission_windows FOR EACH ROW EXECUTE FUNCTION kaname.authority_crud_unique_guard_v3();
CREATE TRIGGER authority_crud_sequence BEFORE INSERT OR UPDATE ON kaname.resource_journal FOR EACH ROW EXECUTE FUNCTION kaname.authority_crud_sequence_guard_v3();
CREATE TRIGGER authority_crud_sequence BEFORE INSERT OR UPDATE ON kaname.fga_outbox FOR EACH ROW EXECUTE FUNCTION kaname.authority_crud_sequence_guard_v3();
CREATE TRIGGER authority_crud_aux_before BEFORE INSERT OR UPDATE OR DELETE ON kaname.issued_account_ids FOR EACH ROW EXECUTE FUNCTION kaname._authority_crud_aux_write_v3();
CREATE TRIGGER authority_crud_aux_after AFTER INSERT OR UPDATE OR DELETE ON kaname.issued_account_ids FOR EACH ROW EXECUTE FUNCTION kaname._authority_crud_aux_write_v3();
CREATE TRIGGER authority_crud_aux_before BEFORE INSERT OR UPDATE OR DELETE ON kaname.project_resource_quotas FOR EACH ROW EXECUTE FUNCTION kaname._authority_crud_aux_write_v3();
CREATE TRIGGER authority_crud_aux_after AFTER INSERT OR UPDATE OR DELETE ON kaname.project_resource_quotas FOR EACH ROW EXECUTE FUNCTION kaname._authority_crud_aux_write_v3();
CREATE TRIGGER authority_crud_aux_before BEFORE INSERT OR UPDATE OR DELETE ON kaname.identity_admission_windows FOR EACH ROW EXECUTE FUNCTION kaname._authority_crud_aux_write_v3();
CREATE TRIGGER authority_crud_aux_after AFTER INSERT OR UPDATE OR DELETE ON kaname.identity_admission_windows FOR EACH ROW EXECUTE FUNCTION kaname._authority_crud_aux_write_v3();
CREATE TRIGGER authority_crud_aux_before BEFORE INSERT OR UPDATE OR DELETE ON kaname.role_grant_orphan FOR EACH ROW EXECUTE FUNCTION kaname._authority_crud_aux_write_v3();
CREATE TRIGGER authority_crud_aux_after AFTER INSERT OR UPDATE OR DELETE ON kaname.role_grant_orphan FOR EACH ROW EXECUTE FUNCTION kaname._authority_crud_aux_write_v3();
CREATE TRIGGER authority_crud_aux_before BEFORE INSERT OR UPDATE OR DELETE ON kaname.role_selector_prune FOR EACH ROW EXECUTE FUNCTION kaname._authority_crud_aux_write_v3();
CREATE TRIGGER authority_crud_aux_after AFTER INSERT OR UPDATE OR DELETE ON kaname.role_selector_prune FOR EACH ROW EXECUTE FUNCTION kaname._authority_crud_aux_write_v3();
CREATE TRIGGER authority_crud_aux_statement BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON kaname.issued_account_ids FOR EACH STATEMENT EXECUTE FUNCTION kaname._authority_crud_aux_statement_v3();
CREATE TRIGGER authority_crud_aux_statement BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON kaname.project_resource_quotas FOR EACH STATEMENT EXECUTE FUNCTION kaname._authority_crud_aux_statement_v3();
CREATE TRIGGER authority_crud_aux_statement BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON kaname.identity_admission_windows FOR EACH STATEMENT EXECUTE FUNCTION kaname._authority_crud_aux_statement_v3();
CREATE TRIGGER authority_crud_aux_statement BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON kaname.role_grant_orphan FOR EACH STATEMENT EXECUTE FUNCTION kaname._authority_crud_aux_statement_v3();
CREATE TRIGGER authority_crud_aux_statement BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON kaname.role_selector_prune FOR EACH STATEMENT EXECUTE FUNCTION kaname._authority_crud_aux_statement_v3();
CREATE TRIGGER authority_crud_aux_statement BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON kaname.resource_journal FOR EACH STATEMENT EXECUTE FUNCTION kaname._authority_crud_aux_statement_v3();
CREATE TRIGGER authority_crud_journal_applied AFTER INSERT ON kaname.resource_journal FOR EACH ROW EXECUTE FUNCTION kaname.authority_crud_journal_applied_v3();
CREATE TRIGGER authority_crud_fga_id_guard BEFORE INSERT ON kaname.fga_outbox FOR EACH ROW EXECUTE FUNCTION kaname.authority_crud_fga_id_guard_v3();
CREATE TRIGGER authority_crud_fga_id_applied AFTER INSERT ON kaname.fga_outbox FOR EACH ROW EXECUTE FUNCTION kaname.authority_crud_fga_id_applied_v3();
CREATE TRIGGER authority_sequence_program_applied_v3 AFTER INSERT ON kaname.resource_journal FOR EACH ROW EXECUTE FUNCTION kaname.authority_sequence_program_applied_v3();
CREATE TRIGGER authority_sequence_program_applied_v3 AFTER INSERT ON kaname.fga_outbox FOR EACH ROW EXECUTE FUNCTION kaname.authority_sequence_program_applied_v3();
CREATE TRIGGER accounts_000_sequence_origin_insert AFTER INSERT ON kaname.accounts FOR EACH ROW EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER accounts_000_sequence_origin_update AFTER UPDATE ON kaname.accounts FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*) EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER accounts_000_sequence_origin_delete BEFORE DELETE ON kaname.accounts FOR EACH ROW EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER projects_000_sequence_origin_insert AFTER INSERT ON kaname.projects FOR EACH ROW EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER projects_000_sequence_origin_update AFTER UPDATE ON kaname.projects FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*) EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER projects_000_sequence_origin_delete BEFORE DELETE ON kaname.projects FOR EACH ROW EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER users_000_sequence_origin_insert AFTER INSERT ON kaname.users FOR EACH ROW EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER users_000_sequence_origin_update AFTER UPDATE ON kaname.users FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*) EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER users_000_sequence_origin_delete BEFORE DELETE ON kaname.users FOR EACH ROW EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER groups_000_sequence_origin_insert AFTER INSERT ON kaname.groups FOR EACH ROW EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER groups_000_sequence_origin_update AFTER UPDATE ON kaname.groups FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*) EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER groups_000_sequence_origin_delete BEFORE DELETE ON kaname.groups FOR EACH ROW EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER service_accounts_000_sequence_origin_insert AFTER INSERT ON kaname.service_accounts FOR EACH ROW EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER service_accounts_000_sequence_origin_update AFTER UPDATE ON kaname.service_accounts FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*) EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER service_accounts_000_sequence_origin_delete BEFORE DELETE ON kaname.service_accounts FOR EACH ROW EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER roles_000_sequence_origin_insert AFTER INSERT ON kaname.roles FOR EACH ROW EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER roles_000_sequence_origin_update AFTER UPDATE ON kaname.roles FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*) EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER roles_000_sequence_origin_delete BEFORE DELETE ON kaname.roles FOR EACH ROW EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER access_bindings_000_sequence_origin_insert AFTER INSERT ON kaname.access_bindings FOR EACH ROW EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER access_bindings_000_sequence_origin_update AFTER UPDATE ON kaname.access_bindings FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*) EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER access_bindings_000_sequence_origin_delete BEFORE DELETE ON kaname.access_bindings FOR EACH ROW EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER group_members_000_sequence_origin AFTER INSERT OR DELETE ON kaname.group_members FOR EACH ROW EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER memberships_000_sequence_origin AFTER INSERT OR DELETE ON kaname.memberships FOR EACH ROW EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
CREATE TRIGGER access_binding_subjects_000_sequence_origin AFTER INSERT OR DELETE ON kaname.access_binding_subjects FOR EACH ROW EXECUTE FUNCTION kaname.authority_sequence_origin_v3();
ALTER TABLE kaname.resource_journal ALTER COLUMN sequence_no SET DEFAULT kaname.authority_resource_journal_id_v3();
ALTER TABLE kaname.fga_outbox ALTER COLUMN id SET DEFAULT kaname.authority_fga_outbox_id_v3();
-- +goose StatementBegin
DO $$ BEGIN IF NOT kaname._authority_full_contract_storage_v3() THEN RAISE EXCEPTION 'full CRUD sequence closure installation incomplete' USING ERRCODE='55000';END IF;END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 PERFORM kaname.authority_protocol_drain();
 IF EXISTS(SELECT 1 FROM kaname.authority_writer_contract WHERE required_contract=2) THEN
  RAISE EXCEPTION 'cannot remove active full CRUD contract' USING ERRCODE='P1036';
 END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.membership_mirror_from_user() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- Первое появление человека: членство, названное колонкой строки,
        -- заводится здесь. Пустой аккаунт пропускается — строка без аккаунта
        -- законна, а членства без аккаунта не бывает.
        IF NEW.account_id IS NOT NULL AND NEW.account_id <> '' THEN
            INSERT INTO kaname.memberships (id, user_id, account_id, state, invited_by, created_at, updated_at)
            VALUES (kaname.membership_mirror_id(NEW.id, NEW.account_id),
                    NEW.id,
                    NEW.account_id,
                    CASE WHEN NEW.invite_status = 'PENDING' THEN 'PENDING' ELSE 'ACTIVE' END,
                    NEW.invited_by,
                    NEW.created_at,
                    now())
            ON CONFLICT (user_id, account_id) DO UPDATE
               SET state      = EXCLUDED.state,
                   invited_by = EXCLUDED.invited_by,
                   updated_at = now()
             WHERE kaname.memberships.state      IS DISTINCT FROM EXCLUDED.state
                OR kaname.memberships.invited_by IS DISTINCT FROM EXCLUDED.invited_by;
        END IF;
    ELSE
        -- Правка строки: зеркало ПРАВИТ существующее членство и НЕ заводит
        -- нового. Снятое членство не возвращается ничем, кроме приглашения.
        UPDATE kaname.memberships m
           SET state      = CASE WHEN NEW.invite_status = 'PENDING' THEN 'PENDING' ELSE 'ACTIVE' END,
               invited_by = NEW.invited_by,
               updated_at = now()
         WHERE m.user_id = NEW.id
           AND m.account_id = NEW.account_id
           AND (m.state      IS DISTINCT FROM CASE WHEN NEW.invite_status = 'PENDING' THEN 'PENDING' ELSE 'ACTIVE' END
             OR m.invited_by IS DISTINCT FROM NEW.invited_by);
    END IF;

    -- Первый вход: человек перестал быть приглашённым — значит приглашённым он
    -- не остаётся НИ В ОДНОМ аккаунте (20260823053000, воспроизведено дословно).
    IF NEW.invite_status <> 'PENDING' THEN
        UPDATE kaname.memberships
           SET state = 'ACTIVE', updated_at = now()
         WHERE user_id = NEW.id AND state = 'PENDING';
    END IF;

    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_resource_write_v2(m jsonb,p_table text,p_op text,p_old jsonb,p_new jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE w jsonb; selected jsonb;
BEGIN
 p_old:=kaname._authority_resource_row_image_v2(p_table,p_old);
 p_new:=kaname._authority_resource_row_image_v2(p_table,p_new);
 FOR w IN SELECT value FROM jsonb_array_elements(m->'writes')
 WHERE value->>'table'=p_table AND value->>'operation'=p_op
 AND value->'old'=p_old AND value->'new'=p_new
 AND value->'command'=m->'object_command' LOOP
  PERFORM kaname._authority_resource_validate_write_v2(m,w);
  IF selected IS NOT NULL AND selected IS DISTINCT FROM w THEN
   RAISE EXCEPTION 'ambiguous resource producer write' USING ERRCODE='42501';
  END IF;
  selected:=w;
 END LOOP;
 IF selected IS NULL THEN RAISE EXCEPTION 'resource row absent from private manifest' USING ERRCODE='42501'; END IF;
 RETURN selected;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_row_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; scope record; manifest jsonb; old_image jsonb; new_image jsonb; matched jsonb;
BEGIN
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NOT NULL THEN
  IF TG_OP<>'INSERT' THEN old_image:=to_jsonb(OLD); END IF;
  IF TG_OP<>'DELETE' THEN new_image:=to_jsonb(NEW); END IF;
  matched:=kaname._authority_resource_write_v2(manifest,TG_TABLE_NAME,TG_OP,old_image,new_image);
  IF TG_TABLE_NAME='fga_outbox' AND TG_OP='INSERT' THEN
   PERFORM kaname._authority_resource_consume_outbox_v2(manifest,matched);
  END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
 END IF;
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

DROP FUNCTION kaname._authority_resource_before_write_v3(jsonb,text,text,jsonb,jsonb);

ALTER TABLE kaname.resource_journal ALTER COLUMN sequence_no SET DEFAULT nextval('kaname.resource_journal_sequence_no_seq'::regclass);
ALTER TABLE kaname.fga_outbox ALTER COLUMN id SET DEFAULT nextval('kaname.fga_outbox_id_seq'::regclass);
DROP TRIGGER access_binding_subjects_000_sequence_origin ON kaname.access_binding_subjects;
DROP TRIGGER memberships_000_sequence_origin ON kaname.memberships;
DROP TRIGGER group_members_000_sequence_origin ON kaname.group_members;
DROP TRIGGER access_bindings_000_sequence_origin_delete ON kaname.access_bindings;
DROP TRIGGER access_bindings_000_sequence_origin_update ON kaname.access_bindings;
DROP TRIGGER access_bindings_000_sequence_origin_insert ON kaname.access_bindings;
DROP TRIGGER roles_000_sequence_origin_delete ON kaname.roles;
DROP TRIGGER roles_000_sequence_origin_update ON kaname.roles;
DROP TRIGGER roles_000_sequence_origin_insert ON kaname.roles;
DROP TRIGGER service_accounts_000_sequence_origin_delete ON kaname.service_accounts;
DROP TRIGGER service_accounts_000_sequence_origin_update ON kaname.service_accounts;
DROP TRIGGER service_accounts_000_sequence_origin_insert ON kaname.service_accounts;
DROP TRIGGER groups_000_sequence_origin_delete ON kaname.groups;
DROP TRIGGER groups_000_sequence_origin_update ON kaname.groups;
DROP TRIGGER groups_000_sequence_origin_insert ON kaname.groups;
DROP TRIGGER users_000_sequence_origin_delete ON kaname.users;
DROP TRIGGER users_000_sequence_origin_update ON kaname.users;
DROP TRIGGER users_000_sequence_origin_insert ON kaname.users;
DROP TRIGGER projects_000_sequence_origin_delete ON kaname.projects;
DROP TRIGGER projects_000_sequence_origin_update ON kaname.projects;
DROP TRIGGER projects_000_sequence_origin_insert ON kaname.projects;
DROP TRIGGER accounts_000_sequence_origin_delete ON kaname.accounts;
DROP TRIGGER accounts_000_sequence_origin_update ON kaname.accounts;
DROP TRIGGER accounts_000_sequence_origin_insert ON kaname.accounts;
DROP TRIGGER authority_sequence_program_applied_v3 ON kaname.fga_outbox;
DROP TRIGGER authority_sequence_program_applied_v3 ON kaname.resource_journal;
DROP TRIGGER authority_crud_fga_id_applied ON kaname.fga_outbox;
DROP TRIGGER authority_crud_fga_id_guard ON kaname.fga_outbox;
DROP TRIGGER authority_crud_journal_applied ON kaname.resource_journal;
DROP TRIGGER authority_crud_aux_statement ON kaname.resource_journal;
DROP TRIGGER authority_crud_aux_statement ON kaname.role_selector_prune;
DROP TRIGGER authority_crud_aux_statement ON kaname.role_grant_orphan;
DROP TRIGGER authority_crud_aux_statement ON kaname.identity_admission_windows;
DROP TRIGGER authority_crud_aux_statement ON kaname.project_resource_quotas;
DROP TRIGGER authority_crud_aux_statement ON kaname.issued_account_ids;
DROP TRIGGER authority_crud_aux_after ON kaname.role_selector_prune;
DROP TRIGGER authority_crud_aux_before ON kaname.role_selector_prune;
DROP TRIGGER authority_crud_aux_after ON kaname.role_grant_orphan;
DROP TRIGGER authority_crud_aux_before ON kaname.role_grant_orphan;
DROP TRIGGER authority_crud_aux_after ON kaname.identity_admission_windows;
DROP TRIGGER authority_crud_aux_before ON kaname.identity_admission_windows;
DROP TRIGGER authority_crud_aux_after ON kaname.project_resource_quotas;
DROP TRIGGER authority_crud_aux_before ON kaname.project_resource_quotas;
DROP TRIGGER authority_crud_aux_after ON kaname.issued_account_ids;
DROP TRIGGER authority_crud_aux_before ON kaname.issued_account_ids;
DROP TRIGGER authority_crud_sequence ON kaname.fga_outbox;
DROP TRIGGER authority_crud_sequence ON kaname.resource_journal;
DROP TRIGGER authority_crud_unique ON kaname.identity_admission_windows;
DROP TRIGGER authority_crud_unique ON kaname.project_resource_quotas;
DROP TRIGGER authority_crud_unique ON kaname.issued_account_ids;
DROP TRIGGER authority_crud_unique ON kaname.service_accounts;
DROP TRIGGER authority_crud_unique ON kaname.projects;
DROP TRIGGER authority_crud_unique ON kaname.accounts;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_resource_assert_body_v2(p_intent jsonb) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;
BEGIN
 manifest:=kaname._authority_resource_manifest_v2();
 IF manifest->>'state' IS DISTINCT FROM 'final' OR p_intent IS DISTINCT FROM manifest->'intent'
 OR manifest->>'decision_at' IS NULL THEN
  RAISE EXCEPTION 'resource closed body requires final manifest' USING ERRCODE='42501';
 END IF;
 -- Resource не является writer личности или каталога. Проверка действует
 -- до смены state на body: даже ошибочный private creator не может включить
 -- SA INSERT/DELETE/reparent и обойти GLOBAL/root защиту absence witness.
 -- Точные разрешённые OLD/NEW оставшихся таблиц дополнительно проверяет
 -- semantic creator; принадлежность этому перечню сама по себе не allow.
 IF jsonb_typeof(manifest->'writes') IS DISTINCT FROM 'array'
 OR jsonb_array_length(manifest->'writes')>100000
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(manifest->'writes') w
  WHERE coalesce(w->>'table','') NOT IN (
   'roles','access_bindings','access_binding_subjects','access_binding_target_members','access_binding_emitted_tuples',
   'role_rule_selectors','role_selector_verbs_pending','role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule',
   'resource_mirror','resource_parent_edge','resource_registration_scope','resource_registration_pointer',
   'resource_registration_retirement','producer_source_receipt','public_read_publication','relation_fact','fga_outbox')) THEN
  RAISE EXCEPTION 'resource manifest contains unsupported write domain' USING ERRCODE='42501';
 END IF;
 -- Второй запуск того же тела в одной TX также отвергается. Изменение
 -- касается только уже открытой private temp строки, новых waits нет.
 UPDATE pg_temp.kaname_authority_resource_manifest SET state='body';
 RETURN true;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_resource_require_completion_v2() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb; physical jsonb; storage oid; consumed integer[]; required_count integer; consumed_count integer;
BEGIN
 storage:=to_regclass('pg_temp.kaname_authority_resource_manifest');
 IF TG_RELID IS DISTINCT FROM storage OR TG_OP<>'INSERT' OR TG_WHEN<>'AFTER'
 OR TG_LEVEL<>'ROW' OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c
  WHERE c.oid=storage AND c.relowner=current_user::regrole::oid AND c.relpersistence='t' AND c.relkind='r') THEN
  RAISE EXCEPTION 'resource completion trigger target invalid' USING ERRCODE='42501';
 END IF;
 manifest:=kaname._authority_resource_manifest_v2();
 IF manifest->>'state' IS DISTINCT FROM 'body'
 OR jsonb_typeof(manifest->'writes') IS DISTINCT FROM 'array'
 OR jsonb_array_length(manifest->'writes')>100000 THEN
  RAISE EXCEPTION 'resource body did not complete' USING ERRCODE='42501';
 END IF;
 SELECT consumed_required_writes INTO STRICT consumed FROM pg_temp.kaname_authority_resource_manifest;
 IF consumed IS NULL OR cardinality(consumed)>100000
 OR EXISTS(SELECT 1 FROM unnest(consumed) n WHERE n IS NULL OR n<1 OR n>jsonb_array_length(manifest->'writes'))
 OR EXISTS(SELECT 1 FROM unnest(consumed) n GROUP BY n HAVING count(*)<>1)
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(manifest->'writes') w WHERE jsonb_typeof(w->'required') IS DISTINCT FROM 'boolean') THEN
  RAISE EXCEPTION 'resource completion inventory is invalid' USING ERRCODE='42501';
 END IF;
 SELECT count(*)::integer INTO required_count FROM jsonb_array_elements(manifest->'writes') w WHERE w->>'required'='true';
 SELECT count(*)::integer INTO consumed_count FROM unnest(consumed) n
  WHERE manifest->'writes'->(n-1)->>'required'='true';
 IF required_count<>consumed_count THEN
  RAISE EXCEPTION 'resource mandatory effect was omitted' USING ERRCODE='42501';
 END IF;
 -- Audit и вспомогательные очереди не входят в authority32; их точное
 -- применение и завершение последней команды проверяются отдельно.
 IF manifest->'intent'->>'kind'='object' THEN
  IF manifest->>'object_program_claimed' IS DISTINCT FROM 'true'
   OR (manifest->>'object_command')::integer IS DISTINCT FROM jsonb_array_length(manifest#>'{object_program,commands}') THEN
   RAISE EXCEPTION 'resource object program did not complete' USING ERRCODE='42501';END IF;
  physical:=manifest->'object_physical';
 ELSIF manifest->'intent'->>'Action' IN ('1','2','3','4','5') THEN
  IF manifest->>'registration_program_claimed' IS DISTINCT FROM 'true'
   OR (manifest->>'object_command')::integer IS DISTINCT FROM jsonb_array_length(manifest#>'{registration_program,commands}') THEN
   RAISE EXCEPTION 'resource registration program did not complete' USING ERRCODE='42501';END IF;
  physical:=manifest->'registration_physical';
  IF jsonb_typeof(physical->'bindings') IS DISTINCT FROM 'array'
   OR jsonb_typeof(physical->'reconcile') IS DISTINCT FROM 'array'
   OR jsonb_typeof(manifest->'consumed_registration_bindings') IS DISTINCT FROM 'array'
   OR jsonb_typeof(manifest->'consumed_reconcile_ids') IS DISTINCT FROM 'array'
   OR jsonb_typeof(physical->'subject_changes') IS DISTINCT FROM 'array'
   OR jsonb_typeof(manifest->'consumed_subject_change_ids') IS DISTINCT FROM 'array'
   OR jsonb_array_length(physical->'subject_changes')<>jsonb_array_length(manifest->'consumed_subject_change_ids')
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(physical->'subject_changes') r
    WHERE NOT (manifest->'consumed_subject_change_ids') @> jsonb_build_array(r->'row'->'id'))
   OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_subject_change_ids') n GROUP BY n HAVING count(*)<>1)
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(physical->'bindings') WITH ORDINALITY e(value,ordinality)
    WHERE e.value->>'required'='true' AND NOT (manifest->'consumed_registration_bindings') @> jsonb_build_array(e.ordinality))
   OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_registration_bindings') n
    WHERE n::integer<1 OR n::integer>jsonb_array_length(physical->'bindings')
     OR physical->'bindings'->(n::integer-1)->>'required' IS DISTINCT FROM 'true')
   OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_registration_bindings') n GROUP BY n HAVING count(*)<>1)
   OR jsonb_array_length(physical->'reconcile')<>jsonb_array_length(manifest->'consumed_reconcile_ids')
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(physical->'reconcile') r
    WHERE NOT (manifest->'consumed_reconcile_ids') @> jsonb_build_array(r->'row'->'id'))
   OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_reconcile_ids') n GROUP BY n HAVING count(*)<>1) THEN
    RAISE EXCEPTION 'resource registration auxiliary effect omitted' USING ERRCODE='42501';END IF;
 ELSE RAISE EXCEPTION 'resource completion intent unsupported' USING ERRCODE='42501';
 END IF;
 IF jsonb_typeof(physical->'audits') IS DISTINCT FROM 'array'
  OR jsonb_typeof(manifest->'consumed_audit_ids') IS DISTINCT FROM 'array'
  OR jsonb_array_length(physical->'audits')<>jsonb_array_length(manifest->'consumed_audit_ids')
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(physical->'audits') a
   WHERE NOT (manifest->'consumed_audit_ids') ? (a->'row'->>'id'))
  OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_audit_ids') identifier GROUP BY identifier HAVING count(*)<>1) THEN
   RAISE EXCEPTION 'resource mandatory audit was omitted' USING ERRCODE='42501';END IF;
 IF jsonb_typeof(manifest->'consumed_object_folds') IS DISTINCT FROM 'array'
  OR jsonb_typeof(physical->'outboxes') IS DISTINCT FROM 'array'
  OR jsonb_array_length(manifest->'consumed_object_folds')<>jsonb_array_length(physical->'outboxes')
  OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_object_folds') n
   WHERE n::integer<1 OR n::integer>jsonb_array_length(physical->'outboxes'))
  OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_object_folds') n GROUP BY n HAVING count(*)<>1) THEN
   RAISE EXCEPTION 'resource mandatory journal fold was omitted' USING ERRCODE='42501';END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_resource_fold_body_v2(p_event_type text,p_payload jsonb,p_created_at timestamptz)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;item jsonb;expected jsonb;row_value jsonb;image jsonb;invoker oid;
 ordinal integer;write_ordinal integer;selected integer:=0;outboxes jsonb;fold_images jsonb;outbox_ordinals jsonb;requires_update boolean:=true;
BEGIN
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NULL THEN RETURN false;END IF;
 IF manifest->'intent'->>'kind'='object' THEN
  outboxes:=manifest#>'{object_physical,outboxes}';fold_images:=manifest#>'{object_fold,images}';
  outbox_ordinals:=manifest->'object_outbox_write_ordinals';
 ELSIF coalesce(manifest->'intent'->>'Action','') IN ('1','2','3','4') THEN
  outboxes:=manifest#>'{registration_physical,outboxes}';fold_images:=manifest#>'{registration_physical,fold_images}';
  outbox_ordinals:=manifest->'registration_outbox_write_ordinals';
 ELSE RAISE EXCEPTION 'resource fold intent unsupported' USING ERRCODE='42501';END IF;
 IF jsonb_typeof(outboxes) IS DISTINCT FROM 'array' OR jsonb_typeof(fold_images) IS DISTINCT FROM 'array'
 OR jsonb_typeof(outbox_ordinals) IS DISTINCT FROM 'array'
 OR jsonb_typeof(manifest->'consumed_object_folds') IS DISTINCT FROM 'array'
 OR jsonb_array_length(outboxes)>100000 OR jsonb_array_length(fold_images)>100000
 OR jsonb_array_length(outbox_ordinals)<>jsonb_array_length(outboxes) THEN
  RAISE EXCEPTION 'resource fold private program unavailable' USING ERRCODE='42501';END IF;
 expected:=jsonb_build_object('event_type',p_event_type,'payload',p_payload,'created_at',p_created_at);
 ordinal:=0;
 FOR item IN SELECT value FROM jsonb_array_elements(outboxes) LOOP
  ordinal:=ordinal+1;
  IF item->'command' IS DISTINCT FROM manifest->'object_command'
  OR item->'row' IS DISTINCT FROM expected OR (manifest->'consumed_object_folds') @> jsonb_build_array(ordinal) THEN CONTINUE;END IF;
  write_ordinal:=(outbox_ordinals->>(ordinal-1))::integer;
  IF write_ordinal IS NULL OR write_ordinal<1 OR write_ordinal>jsonb_array_length(manifest->'writes') THEN
   RAISE EXCEPTION 'resource fold outbox linkage invalid' USING ERRCODE='42501';END IF;
  -- BEFORE INSERT сопоставил exact image, AFTER ROW подтвердил actual INSERT.
  -- Только обе отметки разрешают fold. Операторный journal trigger идёт
  -- после row triggers; попытка ON CONFLICT DO NOTHING не даёт этого права.
  IF NOT (manifest->'consumed_outbox_writes') @> jsonb_build_array(write_ordinal)
  OR NOT (manifest->'consumed_required_writes') @> jsonb_build_array(write_ordinal) THEN CONTINUE;END IF;
  IF selected=0 THEN selected:=ordinal;END IF;
 END LOOP;
 IF selected=0 THEN RAISE EXCEPTION 'resource fold without matching inserted journal' USING ERRCODE='42501';END IF;
 IF manifest->'intent'->>'kind' IS DISTINCT FROM 'object' THEN
  IF jsonb_typeof(outboxes->(selected-1)->'requires_update_acl') IS DISTINCT FROM 'boolean' THEN
   RAISE EXCEPTION 'registration fold row-lock ACL proof missing' USING ERRCODE='42501';END IF;
  requires_update:=(outboxes->(selected-1)->>'requires_update_acl')::boolean;
 END IF;
 invoker:=(manifest->>'invoker_oid')::oid;
 IF manifest->'intent'->>'Action'='2' THEN
  PERFORM kaname._authority_resource_unregistration_operation_acl_v2(manifest#>'{registration_body,acl}',invoker,
   jsonb_build_object('steps',jsonb_build_array(manifest#>'{registration_program,commands}'->((manifest->>'object_command')::integer-1))));
 END IF;
 FOR image IN SELECT value FROM jsonb_array_elements(fold_images) LOOP
  IF (image->>'outbox')::integer IS DISTINCT FROM selected THEN CONTINUE;END IF;
  IF image->>'table' IS DISTINCT FROM 'relation_fact' OR image->>'operation' NOT IN ('INSERT','UPDATE','DELETE') THEN
   RAISE EXCEPTION 'invalid resource folded physical action' USING ERRCODE='42501';END IF;
  -- INSERT исполняет тот же ON CONFLICT UPDATE, поэтому UPDATE image ниже
  -- является его проверяемым исходом, а не второй независимой командой.
  IF image->>'operation'='UPDATE' THEN CONTINUE;END IF;
  IF image->>'operation'='INSERT' THEN
   IF manifest->'intent'->>'Action'='2' THEN
    RAISE EXCEPTION 'cleanup cannot fold a fact write' USING ERRCODE='42501';END IF;
   IF NOT has_table_privilege(invoker,'kaname.relation_fact','SELECT')
   OR NOT has_table_privilege(invoker,'kaname.relation_fact','INSERT')
   OR NOT has_table_privilege(invoker,'kaname.relation_fact','UPDATE') THEN
    RAISE EXCEPTION 'resource fold requires caller fact upsert ACL' USING ERRCODE='42501';END IF;
   row_value:=image->'new';
   INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject,source_version,created_at,condition_name,condition_params)
   VALUES(row_value->>'object_type',row_value->>'object_id',row_value->>'relation',row_value->>'subject',
    (row_value->>'source_version')::timestamptz,(row_value->>'created_at')::timestamptz,
    row_value->>'condition_name',row_value->'condition_params')
   ON CONFLICT(object_type,object_id,relation,subject) DO UPDATE
    SET source_version=EXCLUDED.source_version,condition_name=EXCLUDED.condition_name
    WHERE relation_fact.source_version<EXCLUDED.source_version;
  ELSE
   IF manifest->'intent'->>'Action' IS DISTINCT FROM '2' THEN
    IF NOT has_table_privilege(invoker,'kaname.relation_fact','SELECT')
    OR NOT has_table_privilege(invoker,'kaname.relation_fact','DELETE')
    OR (requires_update AND NOT has_any_column_privilege(invoker,'kaname.relation_fact','UPDATE')) THEN
     RAISE EXCEPTION 'resource fold requires caller fact delete ACL' USING ERRCODE='42501';END IF;
   END IF;
   row_value:=image->'old';
   DELETE FROM ONLY kaname.relation_fact WHERE object_type=row_value->>'object_type' AND object_id=row_value->>'object_id'
    AND relation=row_value->>'relation' AND subject=row_value->>'subject';
  END IF;
 END LOOP;
 UPDATE pg_temp.kaname_authority_resource_manifest SET consumed_object_folds=array_append(consumed_object_folds,selected);
 RETURN true;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_resource_prewait_v2(p_envelope jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;prepared record;
BEGIN
 IF p_rows IS NULL OR p_rows<1 OR p_rows>100000 OR p_reads IS NULL OR p_reads<1 OR p_reads>4096
 OR jsonb_typeof(p_envelope) IS DISTINCT FROM 'object' OR octet_length(p_envelope::text)>67108864 THEN
  RAISE EXCEPTION 'resource prewait input budget exceeded' USING ERRCODE='54000';END IF;
 IF p_envelope->'abi' IS DISTINCT FROM '2'::jsonb OR jsonb_typeof(p_envelope->'intent') IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'resource prewait ABI mismatch' USING ERRCODE='42501';END IF;
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
 OR proof->>'purpose' IS DISTINCT FROM 'participant' OR proof->>'consumer_abi' IS DISTINCT FROM '2'
 OR proof->>'consumer_finalized' IS DISTINCT FROM 'false'
 OR proof->>'consumer_profile' NOT IN ('resource_pending','resource_source_pending')
 OR current_setting('transaction_isolation')<>'read committed'
 OR to_regclass('pg_temp.kaname_authority_resource_manifest') IS NOT NULL THEN
  RAISE EXCEPTION 'resource prewait requires fresh typed participant' USING ERRCODE='42501';END IF;
 IF p_envelope->'intent' ? 'kind' THEN
  IF p_envelope->'intent'->>'kind' IS DISTINCT FROM 'object'
  OR p_envelope->'intent' ? 'Action'
  OR proof->>'consumer_profile' IS DISTINCT FROM 'resource_pending' THEN
   RAISE EXCEPTION 'object route requires exact pending object intent' USING ERRCODE='42501';END IF;
  SELECT * INTO STRICT prepared FROM kaname._authority_resource_object_prepare_v2(p_envelope,p_rows,p_reads);
 ELSE
  -- The closed family dispatcher checks Action and delegates to the complete
  -- direct, withdrawal or refusal compiler. Unknown intents never fall back.
  SELECT * INTO STRICT prepared FROM kaname._authority_resource_registration_prepare_v2(p_envelope,p_rows,p_reads);
 END IF;
 IF prepared.logical_rows IS NULL OR prepared.logical_rows<0 OR prepared.logical_rows>p_rows
 OR prepared.logical_reads IS NULL OR prepared.logical_reads<0 OR prepared.logical_reads>p_reads THEN
  RAISE EXCEPTION 'resource compiler exceeded shared budget' USING ERRCODE='54000';END IF;
 RETURN QUERY SELECT prepared.logical_rows::integer,prepared.logical_reads::integer;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_statement_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; manifest jsonb; allowed boolean;step jsonb;
BEGIN
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NOT NULL THEN
  allowed:=false;
  IF manifest->'intent'->>'kind'='object' THEN
   step:=manifest#>'{object_program,commands}'->((manifest->>'object_command')::integer-1);
   -- Проверяем только текущий выданный private command, не соседние шаги.
   -- Два закрытых UPSERT: members и fact fold команды write. Оба вызывают
   -- statement UPDATE даже без конфликтующей строки или при stale версии.
   -- Синтаксическое UPDATE подтверждает attempted INSERT того же шага;
   -- разрешённые actual row images и обязательность consumption не меняются.
   SELECT manifest->>'object_program_claimed'='true' AND EXISTS(
    SELECT 1 FROM jsonb_array_elements(manifest->'writes') w
    WHERE w->'command'=manifest->'object_command' AND w->>'table'=TG_TABLE_NAME
    AND (w->>'operation'=TG_OP OR
     (TG_OP='UPDATE' AND w->>'operation'='INSERT'
      AND ((step->>'Kind'='members' AND TG_TABLE_NAME='access_binding_target_members')
       OR (step->>'Kind'='write' AND TG_TABLE_NAME='relation_fact'))))) INTO allowed;
  ELSIF manifest->'intent'->>'Action' IN ('1','2','3','4') THEN
   step:=manifest#>'{registration_program,commands}'->((manifest->>'object_command')::integer-1);
   allowed:=manifest->>'registration_program_claimed'='true'
    AND coalesce(step->'operations'->TG_TABLE_NAME,'[]'::jsonb) ? TG_OP;
  END IF;
  IF TG_OP='TRUNCATE' OR NOT coalesce(allowed,false) THEN
   RAISE EXCEPTION 'resource statement absent from current private command' USING ERRCODE='42501';
  END IF;
  RETURN NULL;
 END IF;
 proof:=kaname.authority_protocol_attestation();
 -- kaname#1034: после удаления parent каскадный child уже не обязан видеть
 -- его anchor; role target cascade также может затронуть другой account.
 -- До отдельной proven классификации adapter выбирает global ДО всех locks.
 IF proof IS NOT NULL AND proof->>'mode'<>'global'
 AND (TG_OP='TRUNCATE' OR (TG_OP='DELETE' AND TG_TABLE_NAME IN ('roles','groups','accounts'))) THEN
  RAISE EXCEPTION 'authority truncate or parent cascade requires global intent' USING ERRCODE='42501';
 END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_attestation() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; consumer jsonb; storage oid; lock_mode text;
BEGIN
 -- Невалидная signed attestation здесь бросает ошибку; unsigned fallback нет.
 proof:=kaname._authority_protocol_attestation_v1_body();
 IF proof IS NULL THEN
  PERFORM kaname._authority_compare_legacy_write_allowed_v2();
  -- Compatibility RR/direct/maintenance writer должен войти до первой DML
  -- через общий BEFORE STATEMENT guard. Это единственная unsigned ветка.
  PERFORM pg_advisory_xact_lock(1262569292,0);
  RETURN NULL;
 END IF;
 storage:=to_regclass('pg_temp.kaname_authority_consumer');
 IF storage IS NULL OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=storage
  AND relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)
  AND relpersistence='t' AND relkind='r') THEN
  RAISE EXCEPTION 'authority consumer v2 witness missing' USING ERRCODE='42501';
 END IF;
 SELECT to_jsonb(c) INTO consumer FROM pg_temp.kaname_authority_consumer c;
 IF consumer IS NULL OR consumer->>'abi' IS DISTINCT FROM '2'
 OR consumer->>'backend' IS DISTINCT FROM proof->>'backend'
 OR consumer->>'transaction_id' IS DISTINCT FROM proof->>'transaction_id'
 OR consumer->>'invoker_oid' IS DISTINCT FROM proof->>'invoker_oid'
 OR consumer->>'nonce' IS DISTINCT FROM proof->>'nonce'
 OR consumer->>'profile' NOT IN ('typed','full','resource_pending','resource_source_pending') THEN
  RAISE EXCEPTION 'authority consumer v2 witness mismatch' USING ERRCODE='42501';
 END IF;
 lock_mode:=CASE WHEN proof->>'mode'='global' THEN 'ExclusiveLock' ELSE 'ShareLock' END;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid()
  AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
  AND locktype='advisory' AND classid=1262569292::oid AND objid=0::oid AND objsubid=2
  AND mode=lock_mode AND granted) THEN
  RAISE EXCEPTION 'authority compatibility admission missing' USING ERRCODE='42501';
 END IF;
 IF consumer->>'profile' IN ('typed','full','resource_pending','resource_source_pending') THEN
  lock_mode:=CASE WHEN consumer->>'profile' IN ('typed','full') THEN 'ShareLock' ELSE 'RowExclusiveLock' END;
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid()
   AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
   AND locktype='relation' AND relation='kaname.authority_producer_population_latch'::regclass
   AND mode=lock_mode AND granted)
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid()
   AND locktype='relation' AND relation='kaname.authority_producer_population_latch'::regclass
   AND mode<>lock_mode AND mode<>'AccessShareLock' AND granted) THEN
   RAISE EXCEPTION 'authority population latch mode mismatch' USING ERRCODE='42501';
  END IF;
 END IF;
 RETURN proof||jsonb_build_object('consumer_abi',2,'consumer_profile',consumer->>'profile','consumer_finalized',consumer->'finalized');
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_protocol_attestation_v1_body() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; temp_oid oid; current_invoker oid; strict_mode boolean; k integer; expected_mode text;
BEGIN
 -- Unsigned RR сохраняет locking freshness прежнего протокола. Signed RC
 -- использует только private witness, созданный после successful protocol/identity
 -- FOR SHARE в entry: повторное acquisition после final clock запрещено.
 temp_oid:=to_regclass('pg_temp.kaname_authority_attestation');
 IF temp_oid IS NULL THEN
  SELECT enforcement='strict' INTO STRICT strict_mode FROM kaname.authority_writer_protocol WHERE singleton FOR SHARE;
  IF NOT strict_mode THEN RETURN NULL; END IF;
  RAISE EXCEPTION 'authority transaction attestation required' USING ERRCODE='42501';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=temp_oid AND relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) AND relpersistence='t' AND relkind='r') THEN
  RAISE EXCEPTION 'untrusted authority attestation storage' USING ERRCODE='42501';
 END IF;
 SELECT to_jsonb(a) INTO proof FROM pg_temp.kaname_authority_attestation a;
 IF proof IS NULL THEN
  SELECT enforcement='strict' INTO STRICT strict_mode FROM kaname.authority_writer_protocol WHERE singleton FOR SHARE;
  IF NOT strict_mode THEN RETURN NULL; END IF;
  RAISE EXCEPTION 'authority transaction attestation required' USING ERRCODE='42501';
 END IF;
 SELECT oid INTO STRICT current_invoker FROM pg_catalog.pg_roles WHERE rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
 -- Ряд witness записан тем же entry после получения обоих row locks.
 -- SAVEPOINT rollback, отменяющий их acquisition, отменяет и INSERT witness;
 -- старый witness не проходит xid/backend/nonce и ON COMMIT DELETE ROWS.
 IF current_setting('transaction_isolation')<>'read committed'
 OR (proof->>'backend')::integer<>pg_backend_pid()
 OR (proof->>'transaction_id')::xid8 IS DISTINCT FROM pg_current_xact_id_if_assigned()
 OR (proof->>'invoker_oid')::oid<>current_invoker OR proof->>'nonce' IS NULL
 OR NOT EXISTS(SELECT 1 FROM kaname.authority_writer_contract c WHERE c.singleton AND c.required_contract=(proof->>'writer_contract')::integer)
 OR NOT EXISTS(SELECT 1 FROM kaname.authority_semantic_identity a,kaname.authority_writer_protocol p WHERE a.singleton AND p.singleton AND ((proof->>'purpose' IN ('transition','participant') AND p.enforcement='compatibility' AND a.phase='prepared') OR (proof->>'purpose' IN ('decision','participant') AND p.enforcement='strict' AND a.phase='active')) AND a.protocol_version=(proof->>'protocol')::integer AND p.protocol_version=a.protocol_version AND a.model_id=proof->>'model_id' AND a.catalog_id=proof->>'catalog_id' AND a.projector_version=proof->>'projector_version') THEN
  RAISE EXCEPTION 'authority transaction attestation mismatch' USING ERRCODE='42501';
 END IF;
 expected_mode:=CASE WHEN proof->>'mode'='global' THEN 'ExclusiveLock' ELSE 'ShareLock' END;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()) AND locktype='advisory' AND classid=1262569283::oid AND objid=0::oid AND objsubid=2 AND mode=expected_mode AND granted) THEN
  RAISE EXCEPTION 'authority cluster barrier missing' USING ERRCODE='42501';
 END IF;
 IF proof->>'mode'='accounts' THEN
  FOR k IN SELECT DISTINCT hashtext(value) FROM jsonb_array_elements_text(proof->'accounts') LOOP
   IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()) AND locktype='advisory' AND classid=1262569281::oid AND objid=(k::bigint & 4294967295)::oid AND objsubid=2 AND mode='ExclusiveLock' AND granted) THEN
    RAISE EXCEPTION 'authority account barrier missing' USING ERRCODE='42501';
   END IF;
  END LOOP;
 END IF;
 RETURN proof;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_grant_mutation_preflight(p_profile text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; sequence_id regclass;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR coalesce(proof->>'mode','') NOT IN ('accounts','global') THEN
  RAISE EXCEPTION 'grant mutation requires signed coordinator entry' USING ERRCODE='42501';
 END IF;
 IF NOT coalesce(
   (p_profile='binding' AND proof->>'kind'='binding' AND proof->>'purpose' IN ('decision','participant'))
   OR (p_profile='withdrawal' AND proof->>'kind' IN ('binding','delegation') AND proof->>'purpose'='participant')
   OR (p_profile='delegation' AND proof->>'kind'='delegation' AND proof->>'purpose'='participant'),false) THEN
  RAISE EXCEPTION 'grant mutation profile does not match signed entry' USING ERRCODE='42501';
 END IF;
 IF p_profile='delegation' THEN
  LOCK TABLE kaname.audit_outbox,kaname.authority_binding_epoch,
   kaname.authority_policy_epoch,kaname.grant_delegations IN ROW EXCLUSIVE MODE;
 ELSE
  -- Закрытое объединение: родитель/состав, синхронная свёртка, журналы
  -- событий, эпохи policy/binding и отложенные метаданные носителей. Отзыв GD
  -- добавляет настоящего родителя, не подменяет подписанный kind на Binding.
  LOCK TABLE kaname.access_binding_emitted_tuples,kaname.access_binding_subjects,
   kaname.access_binding_target_members,kaname.access_bindings,kaname.audit_outbox,
   kaname.authority_binding_epoch,kaname.authority_policy_carrier_pending,
   kaname.authority_policy_epoch,kaname.fga_outbox,kaname.relation_fact,
   kaname.resource_journal,kaname.resource_reconcile_outbox,
   kaname.subject_change_outbox IN ROW EXCLUSIVE MODE;
  IF proof->>'kind'='delegation' THEN
   LOCK TABLE kaname.grant_delegations IN ROW EXCLUSIVE MODE;
  END IF;
  -- nextval держит RowExclusiveLock последовательности до конца TX (PG16).
  -- Допустимы пропуски ID, как при откате; бизнес-строки до проверки не меняются.
  FOREACH sequence_id IN ARRAY ARRAY[
   'kaname.fga_outbox_id_seq'::regclass,
   'kaname.resource_journal_sequence_no_seq'::regclass,
   'kaname.resource_reconcile_outbox_id_seq'::regclass,
   'kaname.subject_change_outbox_id_seq'::regclass
  ] LOOP
   IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_catalog.pg_backend_pid()
    AND l.locktype='relation' AND l.relation=sequence_id
    AND l.mode='RowExclusiveLock' AND l.granted) THEN
    PERFORM pg_catalog.nextval(sequence_id);
   END IF;
  END LOOP;
 END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_cluster_admin_preflight(p_type text,p_id text) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; at_time timestamptz;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF NOT coalesce(proof->>'kind'='cluster' AND proof->>'purpose'='participant' AND proof->>'mode'='global',false) THEN
  RAISE EXCEPTION 'cluster final decision entry required' USING ERRCODE='42501';
 END IF;
 IF p_type IS NULL OR p_type NOT IN ('user','service_account') OR p_id IS NULL OR p_id='' OR length(p_id)>64 THEN
  RAISE EXCEPTION 'invalid cluster decision target' USING ERRCODE='22023';
 END IF;
 -- Полный native/source readset, включая scope view, группы, альтернативные
 -- roleless/role carriers, checkpoint и named holders fold-delete. Табличные
 -- locks исключают также absent-row/typed-collision phantom до Commit.
 LOCK TABLE kaname.access_binding_emitted_tuples,kaname.access_binding_subjects,
  kaname.access_binding_target_members,kaname.access_bindings,kaname.accounts,
  kaname.catalog_module,kaname.catalog_resource,kaname.catalog_verb,kaname.clusters,
  kaname.grant_delegations,kaname.group_members,kaname.groups,kaname.memberships,
  kaname.producer_source_receipt,kaname.projects,kaname.public_read_publication,
  kaname.resource_mirror,kaname.resource_parent_edge,kaname.resource_registration_pointer,
  kaname.resource_registration_retirement,kaname.resource_registration_scope,
  kaname.role_bind_role_rule,kaname.role_create_binding_rule,kaname.role_rule_ref,
  kaname.role_rule_selectors,kaname.role_selector_verbs_pending,kaname.role_verb,
  kaname.roles,kaname.service_accounts,kaname.users IN SHARE MODE;
 LOCK TABLE kaname.cluster_admin_grants,kaname.relation_fact,
  kaname.authority_policy_epoch IN SHARE ROW EXCLUSIVE MODE;
 LOCK TABLE kaname.audit_outbox,kaname.fga_outbox IN ROW EXCLUSIVE MODE;
 -- View получает собственный relation lock до часов, не только locks базовых таблиц.
 LOCK TABLE kaname.resource_scope_edge IN ACCESS SHARE MODE;
 PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam:cluster-admin-revoke:cluster_root'));
 -- SELECT FOR UPDATE чужого читателя не конфликтует с SHARE table lock.
 -- Поэтому фактические изменяемые строки ждём отдельно до decision_at.
 PERFORM id FROM kaname.cluster_admin_grants WHERE subject_type=p_type AND subject_id=p_id ORDER BY id FOR UPDATE;
 PERFORM 1 FROM kaname.relation_fact WHERE object_type='cluster' AND object_id='cluster_root'
  AND relation='system_admin' AND subject=p_type||':'||p_id FOR UPDATE;
 PERFORM id FROM kaname.clusters WHERE id='cluster_root' FOR KEY SHARE;
 PERFORM key FROM kaname.authority_policy_epoch WHERE key IN ('*',p_type||':'||p_id) ORDER BY key COLLATE "C" FOR UPDATE;
 -- nextval захватывает sequence lock, а пропущенный ID не является grant.
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_catalog.pg_backend_pid()
  AND l.locktype='relation' AND l.relation='kaname.fga_outbox_id_seq'::regclass
  AND l.mode='RowExclusiveLock' AND l.granted) THEN
  PERFORM pg_catalog.nextval('kaname.fga_outbox_id_seq'::regclass);
 END IF;
 at_time:=pg_catalog.clock_timestamp();
 UPDATE pg_temp.kaname_authority_attestation SET decision_at=at_time;
 RETURN at_time;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.resource_journal_emit() RETURNS trigger
  LANGUAGE plpgsql AS $$
DECLARE
  v_kind  text := TG_ARGV[0];
  v_event text;
  v_json  jsonb;
BEGIN
  IF TG_OP = 'DELETE' THEN
    v_event := 'DELETED';
    v_json  := to_jsonb(OLD);
  ELSIF TG_OP = 'UPDATE' THEN
    v_event := 'UPDATED';
    v_json  := to_jsonb(NEW);
  ELSE
    v_event := 'CREATED';
    v_json  := to_jsonb(NEW);
  END IF;

  INSERT INTO kaname.resource_journal
    (resource_kind, resource_id, project_id, scope, event_type, payload)
  VALUES (
    v_kind,
    v_json->>'id',
    kaname.resource_journal_project(v_kind, v_json),
    kaname.resource_journal_scope(v_kind, v_json),
    v_event,
    jsonb_build_object('id', v_json->>'id'));

  -- BEFORE-триггер, вернувший NULL, ОТМЕНИЛ БЫ снятие. AFTER-триггеру возврат
  -- безразличен, и NULL там — обычная форма.
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NULL;
END;
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.resource_journal_emit_member() RETURNS trigger
  LANGUAGE plpgsql AS $$
DECLARE
  v_kind   text := TG_ARGV[0];
  v_col    text := TG_ARGV[1];
  v_table  text := TG_ARGV[2];
  v_row    jsonb;
  v_owner  text;
  v_ownrow jsonb;
BEGIN
  v_row := CASE WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
  v_owner := v_row->>v_col;
  IF COALESCE(v_owner, '') = '' THEN
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NULL END;
  END IF;

  EXECUTE format('SELECT to_jsonb(t) FROM kaname.%I t WHERE t.id = $1', v_table)
    INTO v_ownrow USING v_owner;

  -- Владельца уже нет: его собственное снятие эмитится своим триггером, а состав
  -- уносит каскад. Второе событие о том же снятии было бы дублем.
  IF v_ownrow IS NULL THEN
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NULL END;
  END IF;

  INSERT INTO kaname.resource_journal
    (resource_kind, resource_id, project_id, scope, event_type, payload)
  VALUES (
    v_kind,
    v_owner,
    kaname.resource_journal_project(v_kind, v_ownrow),
    kaname.resource_journal_scope(v_kind, v_ownrow),
    'UPDATED',
    jsonb_build_object('id', v_owner));

  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NULL END;
END;
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_resource_finalize_v2(p_intent jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(decision_at timestamptz,logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb; expected jsonb; actual jsonb; keys text[]; at_time timestamptz; count_rows integer;
 materialized jsonb;entry jsonb;field text;actual_keys text[];held_keys text[];
BEGIN
 IF p_rows IS NULL OR p_rows<0 OR p_rows>100000 OR p_reads IS NULL OR p_reads<1 OR p_reads>4096 THEN
  RAISE EXCEPTION 'resource final budget exceeded' USING ERRCODE='54000';
 END IF;
 manifest:=kaname._authority_resource_manifest_v2();
 IF manifest->>'state' IS DISTINCT FROM 'prepared' OR p_intent IS DISTINCT FROM manifest->'intent' THEN
  RAISE EXCEPTION 'resource final intent mismatch or repeated final clock' USING ERRCODE='42501';
 END IF;
 expected:=manifest->'native_epochs';
 IF jsonb_typeof(expected) IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'resource native epoch manifest missing' USING ERRCODE='42501';
 END IF;
 SELECT coalesce(array_agg(k),ARRAY[]::text[]) INTO keys FROM jsonb_object_keys(expected) k;
 count_rows:=cardinality(keys);
 IF count_rows>4096 OR count_rows>p_rows THEN
  RAISE EXCEPTION 'resource final epoch budget exceeded' USING ERRCODE='54000';
 END IF;
 -- Отсутствие exact epoch не превращается в нулевую revision. Prewait уже
 -- закрепил каждый ключ и его gap; здесь не INSERT и не FOR SHARE/UPDATE.
 SELECT coalesce(jsonb_object_agg(k,CASE WHEN e.key IS NULL THEN 'null'::jsonb
  ELSE jsonb_build_array(e.generation,e.revision) END),'{}'::jsonb)
 INTO actual FROM unnest(keys) k LEFT JOIN kaname.authority_policy_epoch e ON e.key=k;
 IF actual IS DISTINCT FROM expected THEN
  RAISE EXCEPTION 'resource native source changed' USING ERRCODE='P1034';
 END IF;
 at_time:=clock_timestamp();
 IF manifest->'intent'->>'kind'='object' THEN
  materialized:=kaname._authority_resource_object_materialize_v2(manifest->'object_certificate',
   manifest->'object_effects',manifest->'object_sources',manifest->'object_audit_reservations',
   (manifest->>'transaction_at')::timestamptz,at_time);
  -- Чистая финальная сборка не расширяет preclock maximum: обе TTL ветви
  -- заранее закрыли все logical/physical waits и возможные scope keys.
  FOR entry IN SELECT value FROM jsonb_array_elements(materialized->'writes') LOOP
   FOREACH field IN ARRAY ARRAY['epoch_write_keys','epoch_share_keys','source_guard_write_keys','source_guard_read_keys',
    'binding_epoch_write_scopes','binding_epoch_share_scopes','deferred_carrier_roles'] LOOP
    actual_keys:=kaname._authority_resource_key_array_v2(entry->field,field LIKE 'binding_epoch_%');
    held_keys:=kaname._authority_resource_key_array_v2(manifest->field,field LIKE 'binding_epoch_%');
    IF field IN ('epoch_share_keys','source_guard_read_keys','binding_epoch_share_scopes') THEN
     held_keys:=held_keys||kaname._authority_resource_key_array_v2(manifest->(CASE field
      WHEN 'epoch_share_keys' THEN 'epoch_write_keys' WHEN 'source_guard_read_keys' THEN 'source_guard_write_keys'
      ELSE 'binding_epoch_write_scopes' END),field LIKE 'binding_epoch_%');
    END IF;
    IF NOT actual_keys<@held_keys THEN
     RAISE EXCEPTION 'final object effect exceeds preclock physical maximum' USING ERRCODE='42501';END IF;
   END LOOP;
  END LOOP;
  UPDATE pg_temp.kaname_authority_resource_manifest SET writes=materialized->'writes',
   object_program=materialized->'program',object_physical=materialized->'physical',object_fold=materialized->'fold',
   object_outbox_write_ordinals=materialized->'object_outbox_write_ordinals',
   object_step_obligations=materialized->'step_obligations';
 ELSIF coalesce(manifest->'intent'->>'Action','') IN ('1','2','3','4','5') THEN
  IF manifest->'intent'->>'Action'='5' THEN
   -- A verified negative audit has no installation/native permission to grant.
   -- Its exact one-row body was derived and protected before the final clock.
   IF manifest#>'{registration_authority,refusal_only}' IS DISTINCT FROM 'true'::jsonb
   OR manifest#>'{registration_authority,accounts}' IS DISTINCT FROM '{}'::jsonb
   OR manifest#>'{registration_authority,native_epochs}' IS DISTINCT FROM '{}'::jsonb
   OR manifest#>'{registration_body,writes}' IS DISTINCT FROM '[]'::jsonb
   OR manifest#>>'{registration_certificate,action}' IS DISTINCT FROM '5'
   OR manifest#>>'{registration_body,program,commands,0,kind}' IS DISTINCT FROM 'refusal_audit'
   OR jsonb_array_length(manifest#>'{registration_body,program,commands}') IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'refusal final audit-only invariant invalid' USING ERRCODE='42501';END IF;
  ELSE
   PERFORM kaname._authority_resource_registration_authority_final_v2(manifest->'registration_authority',at_time);
  END IF;
  materialized:=manifest->'registration_body';
  IF manifest->'intent'->>'Action'='2' THEN
   materialized:=kaname._authority_resource_unregistration_materialize_v2(
    materialized->'source_index',materialized->'verified',materialized->'catalog',materialized->'direct',
    materialized->'maximum',materialized->'current',materialized->'reservations',
    (manifest->>'transaction_at')::timestamptz,at_time);
   PERFORM kaname._authority_resource_unregistration_operation_acl_v2(
    manifest#>'{registration_body,acl}',(manifest->>'invoker_oid')::oid,materialized->'cleanup_program');
   materialized:=materialized||jsonb_build_object('acl',manifest#>'{registration_body,acl}');
  END IF;
  IF jsonb_typeof(materialized->'writes') IS DISTINCT FROM 'array'
  OR jsonb_typeof(materialized->'physical') IS DISTINCT FROM 'object'
  OR jsonb_typeof(materialized->'program'->'commands') IS DISTINCT FROM 'array'
  OR jsonb_typeof(materialized->'step_obligations') IS DISTINCT FROM 'object' THEN
   RAISE EXCEPTION 'registration private materialization missing' USING ERRCODE='42501';END IF;
  FOR entry IN SELECT value FROM jsonb_array_elements(materialized->'writes') LOOP
   FOREACH field IN ARRAY ARRAY['epoch_write_keys','epoch_share_keys','source_guard_write_keys','source_guard_read_keys',
    'binding_epoch_write_scopes','binding_epoch_share_scopes','deferred_carrier_roles'] LOOP
    actual_keys:=kaname._authority_resource_key_array_v2(entry->field,field LIKE 'binding_epoch_%');
    held_keys:=kaname._authority_resource_key_array_v2(manifest->field,field LIKE 'binding_epoch_%');
    IF field IN ('epoch_share_keys','source_guard_read_keys','binding_epoch_share_scopes') THEN
     held_keys:=held_keys||kaname._authority_resource_key_array_v2(manifest->(CASE field
      WHEN 'epoch_share_keys' THEN 'epoch_write_keys' WHEN 'source_guard_read_keys' THEN 'source_guard_write_keys'
      ELSE 'binding_epoch_write_scopes' END),field LIKE 'binding_epoch_%');
    END IF;
    IF NOT actual_keys<@held_keys THEN
     RAISE EXCEPTION 'final registration effect exceeds preclock maximum' USING ERRCODE='42501';END IF;
   END LOOP;
  END LOOP;
  UPDATE pg_temp.kaname_authority_resource_manifest SET writes=materialized->'writes',registration_body=materialized,
   registration_program=materialized->'program',registration_physical=materialized->'physical',
   registration_step_obligations=materialized->'step_obligations',
   registration_outbox_write_ordinals=materialized->'registration_outbox_write_ordinals';
 ELSE
  RAISE EXCEPTION 'resource final intent compiler unavailable' USING ERRCODE='42501';
 END IF;
 UPDATE pg_temp.kaname_authority_resource_manifest SET state='final',decision_at=at_time;
 UPDATE pg_temp.kaname_authority_attestation SET decision_at=at_time;
 UPDATE pg_temp.kaname_authority_consumer SET finalized=true;
 RETURN QUERY SELECT at_time,count_rows,1;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_resource_object_prepare_v2(p_envelope jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;source_index jsonb;catalog jsonb;certificate jsonb;effects jsonb;audit_plan jsonb;
 required jsonb;sources jsonb;maximum jsonb;predicates jsonb;policy jsonb;expected_accounts jsonb;
 epoch_result record;current_result record;catalog_result record;audit_result record;relations_result record;bundle_result record;
 held_advisory jsonb;compiled jsonb;entry record;global_required boolean;used_rows integer:=0;used_reads integer:=0;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource' OR proof->>'purpose' IS DISTINCT FROM 'participant'
 OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' IS DISTINCT FROM 'resource_pending'
 OR proof->>'consumer_finalized' IS DISTINCT FROM 'false' OR current_setting('transaction_isolation')<>'read committed'
 OR to_regclass('pg_temp.kaname_authority_resource_manifest') IS NOT NULL THEN
  RAISE EXCEPTION 'object prewait requires fresh pending RC admission' USING ERRCODE='42501';END IF;
 IF p_rows IS NULL OR p_rows<1 OR p_rows>100000 OR p_reads IS NULL OR p_reads<1 OR p_reads>4096
 OR jsonb_typeof(p_envelope) IS DISTINCT FROM 'object' OR octet_length(p_envelope::text)>67108864 THEN
  RAISE EXCEPTION 'object prewait budget exceeded' USING ERRCODE='54000';END IF;
 IF p_envelope->>'abi' IS DISTINCT FROM '2' OR p_envelope->'intent'->>'kind' IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_envelope->'object_effects') IS DISTINCT FROM 'object'
 OR p_envelope ? 'registration_effects'
 OR coalesce(nullif(p_envelope->'registration_accounts','null'::jsonb),'[]'::jsonb)<>'[]'::jsonb
 OR coalesce(nullif(p_envelope->'source_effects','null'::jsonb),'[]'::jsonb)<>'[]'::jsonb
 OR coalesce(nullif(p_envelope->'installation','null'::jsonb),'[]'::jsonb)<>'[]'::jsonb
 OR coalesce(nullif(p_envelope->'native_guards','null'::jsonb),'[]'::jsonb)<>'[]'::jsonb
 OR p_envelope->'native_epochs' IS DISTINCT FROM '{}'::jsonb
 OR coalesce(p_envelope->>'actor','')<>'' OR coalesce(p_envelope->>'service','')<>'' THEN
  RAISE EXCEPTION 'object prewait contains foreign operation authority' USING ERRCODE='42501';END IF;
 SELECT * INTO STRICT bundle_result FROM kaname._authority_resource_bundle_catalog_v2(p_rows,p_reads);
 catalog:=bundle_result.catalog;used_rows:=used_rows+bundle_result.logical_rows;used_reads:=used_reads+bundle_result.logical_reads;
 -- Декодирование RR строк не является новым DB чтением; их исходный read
 -- уже входит в shared attempt budget. Каждый used predicate перечитывается ниже.
 source_index:=kaname._authority_resource_capture_index_v2(p_envelope->'sources',100000);
 effects:=p_envelope->'object_effects';
 certificate:=kaname._authority_resource_object_certificate_v2(source_index,catalog,p_envelope->'intent',effects);
 audit_plan:=kaname._authority_resource_audit_plan_v2(source_index,effects->'bindings',effects->'audit_ids');
 required:=(certificate->'required')||(audit_plan->'required');
 sources:=kaname._authority_resource_object_physical_sources_v2(source_index,required);
 maximum:=kaname._authority_resource_object_maximum_v2(certificate,sources,audit_plan,effects);
 -- Исторический delete fold делает SELECT ... FOR UPDATE. Это требует
 -- UPDATE хотя бы одной колонки, даже если позднее DML только DELETE.
 -- Protocol-only source FOR SHARE не превращает все read ACL в write ACL.
 IF (maximum#>'{operations,relation_fact}') ? 'DELETE'
 AND NOT has_any_column_privilege((proof->>'invoker_oid')::oid,'kaname.relation_fact','UPDATE') THEN
  RAISE EXCEPTION 'legacy fact delete row lock requires UPDATE privilege' USING ERRCODE='42501';END IF;
 predicates:=kaname._authority_resource_predicate_maximum_v2(source_index,required);
 -- WRITE побеждает SHARE при совпадении. Нет позднего повышения режима.
 policy:=(predicates->'policy_epochs')||(maximum->'policy_epochs');
 maximum:=jsonb_set(maximum,'{policy_epochs}',policy);
 global_required:=(certificate->>'global')::boolean OR (predicates->>'global')::boolean;
 IF global_required IS NULL OR (proof->>'mode'='global') IS DISTINCT FROM global_required THEN
  RAISE EXCEPTION 'object scope classification changed before physical entry' USING ERRCODE='P1034';END IF;
 SELECT coalesce(jsonb_agg(k ORDER BY k COLLATE "C"),'[]'::jsonb) INTO expected_accounts
  FROM jsonb_object_keys(certificate->'accounts') k;
 IF NOT global_required AND (expected_accounts='[]'::jsonb OR proof->'accounts' IS DISTINCT FROM expected_accounts) THEN
  RAISE EXCEPTION 'object complete mutation accounts differ from admission' USING ERRCODE='P1034';END IF;
 IF (SELECT count(*) FROM jsonb_object_keys(policy))+(SELECT count(*) FROM jsonb_object_keys(maximum->'source_guards'))
  +(SELECT count(*) FROM jsonb_object_keys(maximum->'binding_epochs'))>4096 THEN
  RAISE EXCEPTION 'object complete lock key budget exceeded' USING ERRCODE='54000';END IF;
 SELECT * INTO STRICT epoch_result FROM kaname._authority_resource_epoch_wait_v2(maximum->'source_guards',policy,
  maximum->'binding_epochs',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+epoch_result.logical_rows;used_reads:=used_reads+epoch_result.logical_reads;
 SELECT * INTO STRICT catalog_result FROM kaname._authority_resource_catalog_wait_v2(p_envelope->'catalogs',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+catalog_result.logical_rows;used_reads:=used_reads+catalog_result.logical_reads;
 -- Каждый фактический output тип должен иметь current catalog capture;
 -- arbitrary дополнительная строка не заменяет отсутствующий required тип.
 FOR entry IN SELECT * FROM jsonb_each(certificate->'graphs') LOOP
  IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(catalog_result.catalog_rows) c
   WHERE c->>'dotted'=entry.value->>'object_type' AND c->>'object_type'=entry.value->>'model_type') THEN
   RAISE EXCEPTION 'object graph catalog capture omitted' USING ERRCODE='42501';END IF;
 END LOOP;
 SELECT * INTO STRICT current_result FROM kaname._authority_resource_required_reread_v2(source_index,required,
  sources->'write_keys',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+current_result.logical_rows;used_reads:=used_reads+current_result.logical_reads;
 IF current_result.predicate_protections IS DISTINCT FROM predicates->'protections' THEN
  RAISE EXCEPTION 'object current predicate maximum changed' USING ERRCODE='P1034';END IF;
 -- Пустой server-derived набор не требует чужих ACL или relation locks.
 -- Семантический certificate и полный current reread при этом обязательны.
 IF audit_plan->'ids'='{}'::jsonb THEN
  SELECT '[]'::jsonb AS lock_witness,0 AS logical_rows,0 AS logical_reads INTO audit_result;
 ELSE
  SELECT * INTO STRICT audit_result FROM kaname._authority_resource_audit_wait_v2(audit_plan->'ids',p_rows-used_rows,p_reads-used_reads);
 END IF;
 used_rows:=used_rows+audit_result.logical_rows;used_reads:=used_reads+audit_result.logical_reads;
 IF maximum->'operations'='{}'::jsonb THEN
  SELECT '[]'::jsonb AS lock_witness,0 AS logical_reads INTO relations_result;
 ELSE
  SELECT * INTO STRICT relations_result FROM kaname._authority_resource_physical_relations_wait_v2(maximum->'operations',p_reads-used_reads);
 END IF;
 used_reads:=used_reads+relations_result.logical_reads;
 IF used_rows>p_rows OR used_reads>p_reads THEN RAISE EXCEPTION 'object prewait aggregate budget exceeded' USING ERRCODE='54000';END IF;
 held_advisory:=(epoch_result.lock_witness->'held_advisory')||audit_result.lock_witness;
 compiled:=jsonb_build_object('intent',p_envelope->'intent','certificate',certificate,'effects',effects,'sources',sources,
  'audit_reservations',audit_plan->'reservations','maximum',maximum,'epoch_witness',epoch_result.lock_witness,
  'catalog_rows',catalog_result.catalog_rows,'held_relations',relations_result.lock_witness,'held_advisory',held_advisory);
 PERFORM kaname._authority_resource_object_store_v2(compiled);
 RETURN QUERY SELECT used_rows,used_reads;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_resource_object_program_v2(p_bindings jsonb,p_at timestamptz)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE item jsonb;command jsonb;tuple_value jsonb;tuples jsonb;branch jsonb;
 result jsonb:='[]'::jsonb;pending jsonb:='[]'::jsonb;seen jsonb:='{}'::jsonb;bindings jsonb:='{}'::jsonb;
 identifier text;kind text;tuple_key text;work integer:=0;
BEGIN
 IF p_at IS NULL OR jsonb_typeof(p_bindings) IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'invalid verified object program' USING ERRCODE='42501';END IF;
 IF jsonb_array_length(p_bindings)>4096 OR octet_length(p_bindings::text)>67108864 THEN
  RAISE EXCEPTION 'object program budget exceeded' USING ERRCODE='54000';END IF;
 -- Сортировка носителей совпадает с immutable proposal. Она не является
 -- полной выборкой БД и ограничена уже проверенным числом носителей.
 FOR item IN SELECT value FROM jsonb_array_elements(p_bindings) ORDER BY value->>'binding' COLLATE "C" LOOP
  identifier:=item->>'binding';
  IF coalesce(identifier,'')='' OR bindings ? identifier
  OR jsonb_typeof(item->'active') IS DISTINCT FROM 'boolean'
  OR jsonb_typeof(item->'live') IS DISTINCT FROM 'array'
  OR jsonb_typeof(item->'expired') IS DISTINCT FROM 'array' THEN
   RAISE EXCEPTION 'invalid verified carrier program' USING ERRCODE='42501';END IF;
  bindings:=bindings||jsonb_build_object(identifier,true);
  branch:=CASE WHEN (item->>'active')::boolean AND
   (item->>'expires_at' IS NULL OR (item->>'expires_at')::timestamptz>p_at)
   THEN item->'live' ELSE item->'expired' END;
  FOR command IN SELECT value FROM jsonb_array_elements(branch) LOOP
   work:=work+1;kind:=command->>'Kind';
   IF kind IS NULL OR kind NOT IN ('members','record','forget','write','delete','member_delete','audit') THEN
    RAISE EXCEPTION 'unsupported verified object operation' USING ERRCODE='42501';END IF;
   IF kind='delete' THEN
    -- Все удаления остаются в хвосте; окончательное вычитание выполняется
    -- только после writes ВСЕХ выбранных по final TTL носителей.
    pending:=pending||jsonb_build_array(command);
   ELSIF kind='write' THEN
    IF jsonb_typeof(command->'Tuples') IS DISTINCT FROM 'array' THEN
     RAISE EXCEPTION 'invalid verified write tuple set' USING ERRCODE='42501';END IF;
    tuples:='[]'::jsonb;
    FOR tuple_value IN SELECT value FROM jsonb_array_elements(command->'Tuples') LOOP
     work:=work+1;
     IF work>100000 THEN RAISE EXCEPTION 'object program work exceeded' USING ERRCODE='54000';END IF;
     tuple_key:=tuple_value::text;
     IF NOT seen ? tuple_key THEN
      seen:=seen||jsonb_build_object(tuple_key,true);tuples:=tuples||jsonb_build_array(tuple_value);
     END IF;
    END LOOP;
    IF jsonb_array_length(tuples)>0 THEN result:=result||jsonb_build_array(jsonb_set(command,'{Tuples}',tuples));END IF;
   ELSE result:=result||jsonb_build_array(command);
   END IF;
   IF work>100000 THEN RAISE EXCEPTION 'object program work exceeded' USING ERRCODE='54000';END IF;
  END LOOP;
 END LOOP;
 FOR command IN SELECT value FROM jsonb_array_elements(pending) LOOP
  IF jsonb_typeof(command->'Tuples') IS DISTINCT FROM 'array' THEN
   RAISE EXCEPTION 'invalid verified delete tuple set' USING ERRCODE='42501';END IF;
  tuples:='[]'::jsonb;
  FOR tuple_value IN SELECT value FROM jsonb_array_elements(command->'Tuples') LOOP
   work:=work+1;
   IF work>100000 THEN RAISE EXCEPTION 'object program work exceeded' USING ERRCODE='54000';END IF;
   IF NOT seen ? tuple_value::text THEN tuples:=tuples||jsonb_build_array(tuple_value);END IF;
  END LOOP;
  IF jsonb_array_length(tuples)>0 THEN result:=result||jsonb_build_array(jsonb_set(command,'{Tuples}',tuples));END IF;
  IF work>100000 THEN RAISE EXCEPTION 'object program work exceeded' USING ERRCODE='54000';END IF;
 END LOOP;
 RETURN jsonb_build_object('commands',result,'work',work);
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_resource_physical_relations_capture_v2(p_operations jsonb,p_reads integer,p_defer_acl boolean)
RETURNS TABLE(lock_witness jsonb,logical_reads integer,acl_capabilities jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 proof jsonb; invoker oid; role_name text; entry record; operation jsonb; relation_row record;
 relations jsonb:='[]'::jsonb; locks jsonb:='[]'::jsonb; item jsonb;capabilities jsonb:='{}';table_acl jsonb;allowed boolean;
 table_count integer; operation_count integer:=0; used_reads integer:=0; reserved_reads integer;
 relation_oid oid; outbox_oid oid; sequence_oid oid; sequence_name text; id_attnum smallint;
 needs_sequence boolean; ownership_ok boolean; default_ok boolean;
BEGIN
 IF p_defer_acl IS NULL THEN RAISE EXCEPTION 'resource ACL capture mode missing' USING ERRCODE='42501';END IF;
 IF p_reads IS NULL OR p_reads<0 OR p_reads>4096 THEN
  RAISE EXCEPTION 'invalid resource relation read budget' USING ERRCODE='54000';
 END IF;
 IF jsonb_typeof(p_operations) IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'resource relation operations must be an object' USING ERRCODE='42501';
 END IF;
 -- Лимит размера проверяется до разворачивания JSON; audit имеет отдельный слот.
 IF octet_length(p_operations::text)>16384 THEN
  RAISE EXCEPTION 'resource relation operations exceeded' USING ERRCODE='54000';
 END IF;
 SELECT count(*) INTO table_count FROM jsonb_object_keys(p_operations);
 IF table_count=0 OR table_count-(CASE WHEN p_operations ? 'audit_outbox' THEN 1 ELSE 0 END)>32 THEN
  RAISE EXCEPTION 'invalid resource relation width' USING ERRCODE='42501';
 END IF;
 FOR entry IN SELECT key,value FROM jsonb_each(p_operations) LOOP
  IF entry.key NOT IN (
   'roles','access_bindings','access_binding_subjects','access_binding_target_members','access_binding_emitted_tuples',
   'role_rule_selectors','role_selector_verbs_pending','role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule',
   'resource_mirror','resource_parent_edge','resource_registration_scope','resource_registration_pointer',
   'resource_registration_retirement','producer_source_receipt','public_read_publication','relation_fact','fga_outbox',
   'audit_outbox') OR jsonb_typeof(entry.value) IS DISTINCT FROM 'array' THEN
   RAISE EXCEPTION 'unsupported resource relation or operation array' USING ERRCODE='42501';
  END IF;
  IF jsonb_array_length(entry.value) NOT BETWEEN 1 AND 3 THEN
   RAISE EXCEPTION 'invalid resource operation count' USING ERRCODE='42501';
  END IF;
  FOR operation IN SELECT value FROM jsonb_array_elements(entry.value) LOOP
   IF jsonb_typeof(operation) IS DISTINCT FROM 'string' OR operation #>> '{}' NOT IN ('INSERT','UPDATE','DELETE') THEN
    RAISE EXCEPTION 'unsupported resource operation' USING ERRCODE='42501';
   END IF;
  END LOOP;
  IF (SELECT count(DISTINCT value) FROM jsonb_array_elements(entry.value))<>jsonb_array_length(entry.value) THEN
   RAISE EXCEPTION 'duplicate resource operation' USING ERRCODE='42501';
  END IF;
  operation_count:=operation_count+jsonb_array_length(entry.value);
 END LOOP;
 needs_sequence:=coalesce((p_operations->'fga_outbox') ? 'INSERT',false);
 -- Конечная верхняя граница включает admission, каталоги, ACL, acquisitions
 -- и повторные точечные проверки. Возвращается фактически списанное число.
 reserved_reads:=3+6*table_count+operation_count+CASE WHEN needs_sequence THEN 12 ELSE 0 END
  +CASE WHEN p_defer_acl AND p_operations ? 'relation_fact' THEN 1 ELSE 0 END;
 IF reserved_reads>p_reads THEN
  RAISE EXCEPTION 'resource relation read budget exceeded' USING ERRCODE='54000';
 END IF;
 used_reads:=used_reads+1;
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
 OR proof->>'purpose' IS DISTINCT FROM 'participant'
 OR coalesce(proof->>'consumer_profile','') NOT IN ('resource_pending','resource_source_pending')
 OR proof->>'consumer_abi' IS DISTINCT FROM '2'
 OR proof->>'consumer_finalized' IS DISTINCT FROM 'false'
 OR current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'resource relation wait requires pending RC ABI2 admission' USING ERRCODE='42501';
 END IF;
 role_name:=current_setting('role',true);
 IF role_name IS NULL OR role_name='none' THEN role_name:=session_user;END IF;
 used_reads:=used_reads+1;
 SELECT oid INTO invoker FROM pg_catalog.pg_roles WHERE rolname=role_name;
 IF invoker IS NULL OR proof->>'invoker_oid' IS DISTINCT FROM invoker::text THEN
  RAISE EXCEPTION 'resource relation invoker mismatch' USING ERRCODE='42501';
 END IF;
 used_reads:=used_reads+1;
 IF NOT has_schema_privilege(invoker,'kaname','USAGE') THEN
  RAISE EXCEPTION 'resource relation requires caller schema usage' USING ERRCODE='42501';
 END IF;
 -- Вся проверка обычного invoker завершается до первого LOCK/nextval.
 -- SELECT нужен predicates UPDATE/DELETE. INSERT-only без RETURNING
 -- не получает дополнительного ACL требования; current-image readers и
 -- audit reservation проверяет creator отдельно до своих чтений. Closure
 -- включает UPDATE для syntactic ON CONFLICT DO UPDATE даже без UPDATE image.
 FOR entry IN SELECT key,value FROM jsonb_each(p_operations) ORDER BY key COLLATE "C" LOOP
  used_reads:=used_reads+1;
  SELECT c.oid,c.relkind,c.relpersistence INTO relation_row
   FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='kaname' AND c.relname=entry.key;
  IF NOT FOUND OR relation_row.relkind<>'r' OR relation_row.relpersistence<>'p' THEN
   RAISE EXCEPTION 'resource target must be a permanent ordinary table' USING ERRCODE='42501';
  END IF;
  relation_oid:=relation_row.oid;
  used_reads:=used_reads+1;
  IF EXISTS(SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid=relation_oid OR inhparent=relation_oid) THEN
   RAISE EXCEPTION 'resource inherited target requires a separate physical closure' USING ERRCODE='42501';
  END IF;
  used_reads:=used_reads+1;
  table_acl:='{}';
  IF entry.value ? 'UPDATE' OR entry.value ? 'DELETE' THEN
   allowed:=has_table_privilege(invoker,relation_oid,'SELECT');
   table_acl:=table_acl||jsonb_build_object('SELECT',allowed);
   IF NOT allowed AND NOT p_defer_acl THEN
    RAISE EXCEPTION 'resource relation requires caller SELECT' USING ERRCODE='42501';END IF;
  END IF;
  FOR operation IN SELECT value FROM jsonb_array_elements(entry.value) LOOP
   used_reads:=used_reads+1;allowed:=has_table_privilege(invoker,relation_oid,operation #>> '{}');
   table_acl:=table_acl||jsonb_build_object(operation #>> '{}',allowed);
   IF NOT allowed AND NOT p_defer_acl THEN
    RAISE EXCEPTION 'resource relation requires caller % on %',operation #>> '{}',entry.key USING ERRCODE='42501';
   END IF;
  END LOOP;
  capabilities:=capabilities||jsonb_build_object(entry.key,table_acl);
  IF p_defer_acl AND entry.key='relation_fact' THEN
   used_reads:=used_reads+1;
   capabilities:=capabilities||jsonb_build_object('$fact_row_lock_update',has_any_column_privilege(invoker,relation_oid,'UPDATE'));
  END IF;
  relations:=relations||jsonb_build_array(jsonb_build_object('oid',relation_oid,'name',entry.key,'kind','table'));
  IF entry.key='fga_outbox' THEN outbox_oid:=relation_oid;END IF;
 END LOOP;
 IF needs_sequence THEN
  used_reads:=used_reads+1;
  sequence_name:=pg_get_serial_sequence('kaname.fga_outbox','id');
  IF sequence_name IS NULL THEN
   RAISE EXCEPTION 'resource outbox owned sequence missing' USING ERRCODE='42501';
  END IF;
  used_reads:=used_reads+1;
  SELECT c.oid INTO sequence_oid FROM pg_catalog.pg_class c
   WHERE c.oid=to_regclass(sequence_name) AND c.relkind='S' AND c.relpersistence='p';
  used_reads:=used_reads+1;
  SELECT a.attnum INTO id_attnum FROM pg_catalog.pg_attribute a
   WHERE a.attrelid=outbox_oid AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped;
  IF sequence_oid IS NULL OR id_attnum IS NULL THEN
   RAISE EXCEPTION 'resource outbox sequence identity invalid' USING ERRCODE='42501';
  END IF;
  used_reads:=used_reads+1;
  SELECT count(*)=1 AND coalesce(bool_and(d.refclassid='pg_catalog.pg_class'::regclass
   AND d.refobjid=outbox_oid AND d.refobjsubid=id_attnum AND d.deptype='a'),false)
   INTO ownership_ok FROM pg_catalog.pg_depend d
   WHERE d.classid='pg_catalog.pg_class'::regclass AND d.objid=sequence_oid AND d.objsubid=0 AND d.deptype IN ('a','i');
  used_reads:=used_reads+1;
  SELECT coalesce(bool_and(pg_get_expr(d.adbin,d.adrelid)=format('nextval(%L::regclass)',sequence_oid::regclass::text)),false)
   INTO default_ok FROM pg_catalog.pg_attrdef d WHERE d.adrelid=outbox_oid AND d.adnum=id_attnum;
  IF NOT ownership_ok OR NOT default_ok THEN
   RAISE EXCEPTION 'resource outbox sequence ownership or default mismatch' USING ERRCODE='42501';
  END IF;
  used_reads:=used_reads+1;
  allowed:=has_sequence_privilege(invoker,sequence_oid,'USAGE,UPDATE');
  capabilities:=capabilities||jsonb_build_object('$fga_nextval',allowed);
  IF NOT allowed AND NOT p_defer_acl THEN
   RAISE EXCEPTION 'resource outbox requires caller sequence privilege' USING ERRCODE='42501';
  END IF;
  relations:=relations||jsonb_build_array(jsonb_build_object('oid',sequence_oid,'kind','sequence'));
 END IF;
 -- Единый порядок actual OID включает sequence; значение nextval выбрасывается.
 -- Body оставляет штатный default nextval. Здесь нет ID reservation/reset.
 FOR item IN SELECT value FROM jsonb_array_elements(relations) ORDER BY (value->>'oid')::oid LOOP
  relation_oid:=(item->>'oid')::oid;
  used_reads:=used_reads+1;
  IF item->>'kind'='sequence' THEN
   PERFORM pg_catalog.nextval(relation_oid::regclass);
  ELSE
   EXECUTE format('LOCK TABLE ONLY kaname.%I IN ROW EXCLUSIVE MODE',item->>'name');
   used_reads:=used_reads+1;
   IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE c.oid=relation_oid AND n.nspname='kaname' AND c.relname=item->>'name'
    AND c.relkind='r' AND c.relpersistence='p'
    AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid)) THEN
    RAISE EXCEPTION 'resource target changed during relation acquisition' USING ERRCODE='P1034';
   END IF;
  END IF;
  -- Witness возникает только после acquisition и точечной проверки удержания.
  used_reads:=used_reads+1;
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_backend_pid()
   AND l.locktype='relation' AND l.relation=relation_oid AND l.mode='RowExclusiveLock' AND l.granted) THEN
   RAISE EXCEPTION 'resource RowExclusive acquisition missing' USING ERRCODE='42501';
  END IF;
  locks:=locks||jsonb_build_array(jsonb_build_object('oid',relation_oid,'mode','RowExclusiveLock'));
 END LOOP;
 IF needs_sequence THEN
  -- DDL между catalog lookup и acquisition не становится новой authority.
  used_reads:=used_reads+1;
  IF pg_get_serial_sequence('kaname.fga_outbox','id')::regclass::oid IS DISTINCT FROM sequence_oid THEN
   RAISE EXCEPTION 'resource outbox sequence changed during acquisition' USING ERRCODE='P1034';
  END IF;
  used_reads:=used_reads+1;
  SELECT count(*)=1 AND coalesce(bool_and(d.refclassid='pg_catalog.pg_class'::regclass
   AND d.refobjid=outbox_oid AND d.refobjsubid=id_attnum AND d.deptype='a'),false)
   INTO ownership_ok FROM pg_catalog.pg_depend d
   WHERE d.classid='pg_catalog.pg_class'::regclass AND d.objid=sequence_oid AND d.objsubid=0 AND d.deptype IN ('a','i');
  used_reads:=used_reads+1;
  SELECT coalesce(bool_and(pg_get_expr(d.adbin,d.adrelid)=format('nextval(%L::regclass)',sequence_oid::regclass::text)),false)
   INTO default_ok FROM pg_catalog.pg_attrdef d WHERE d.adrelid=outbox_oid AND d.adnum=id_attnum;
  IF NOT ownership_ok OR NOT default_ok THEN
   RAISE EXCEPTION 'resource outbox sequence binding changed during acquisition' USING ERRCODE='P1034';
  END IF;
 END IF;
 IF used_reads>p_reads OR used_reads>4096 THEN
  RAISE EXCEPTION 'resource relation read budget exceeded' USING ERRCODE='54000';
 END IF;
 RETURN QUERY SELECT locks,used_reads,jsonb_build_object('invoker_oid',invoker,'operations',capabilities);
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_resource_registration_direct_prepare_v2(p_envelope jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;source_index jsonb;certificate jsonb;sources jsonb;program jsonb;maximum jsonb;predicates jsonb;policy jsonb;
 reservations jsonb;materialized jsonb;compiled jsonb;held_relations jsonb;held_advisory jsonb;required jsonb;operations jsonb;
 expected_accounts jsonb;key_value text;entry record;global_required boolean;requires_update boolean;
 bundle_result record;catalog_result record;epoch_result record;current_result record;authority_result record;
 binding_result record;audit_result record;reconcile_result record;relation_result record;
 used_rows integer:=0;used_reads integer:=0;action_value integer;audit_id text;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource' OR proof->>'purpose' IS DISTINCT FROM 'participant'
 OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' IS DISTINCT FROM 'resource_pending'
 OR proof->>'consumer_finalized' IS DISTINCT FROM 'false' OR current_setting('transaction_isolation')<>'read committed'
 OR to_regclass('pg_temp.kaname_authority_resource_manifest') IS NOT NULL THEN
  RAISE EXCEPTION 'registration direct compiler requires fresh pending RC admission' USING ERRCODE='42501';END IF;
 IF p_rows IS NULL OR p_rows<1 OR p_rows>100000 OR p_reads IS NULL OR p_reads<1 OR p_reads>4096
 OR jsonb_typeof(p_envelope) IS DISTINCT FROM 'object' OR octet_length(p_envelope::text)>67108864 THEN
  RAISE EXCEPTION 'registration direct compiler input exceeded' USING ERRCODE='54000';END IF;
 IF coalesce(p_envelope->'intent'->>'Action','') NOT IN ('1','3','4')
 OR coalesce(nullif(p_envelope->'source_effects','null'::jsonb),'[]'::jsonb)<>'[]'::jsonb THEN
  RAISE EXCEPTION 'registration direct compiler cannot admit source mutation' USING ERRCODE='42501';END IF;
 action_value:=(p_envelope->'intent'->>'Action')::integer;
 SELECT * INTO STRICT bundle_result FROM kaname._authority_resource_bundle_catalog_v2(p_rows,p_reads);
 used_rows:=used_rows+bundle_result.logical_rows;used_reads:=used_reads+bundle_result.logical_reads;
 SELECT * INTO STRICT catalog_result FROM kaname._authority_resource_catalog_wait_v2(p_envelope->'catalogs',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+catalog_result.logical_rows;used_reads:=used_reads+catalog_result.logical_reads;
 source_index:=kaname._authority_resource_capture_index_v2(p_envelope->'sources',100000);
 certificate:=kaname._authority_resource_registration_intent_certificate_v2(source_index,bundle_result.catalog,catalog_result.catalog_rows,p_envelope);
 sources:=kaname._authority_resource_registration_direct_sources_v2(source_index,certificate);
 IF action_value=1 THEN
  program:=kaname._authority_resource_registration_direct_program_v2(certificate,sources->'before',transaction_timestamp());
 ELSE
  program:=kaname._authority_resource_publication_direct_program_v2(certificate,sources->'before',transaction_timestamp());
 END IF;
 maximum:=kaname._authority_resource_registration_maximum_v2(source_index,certificate,sources,program,p_envelope->'native_guards');
 required:=maximum->'required';predicates:=kaname._authority_resource_predicate_maximum_v2(source_index,required);
 policy:=(predicates->'policy_epochs')||(maximum->'policy_epochs');
 maximum:=jsonb_set(maximum,'{policy_epochs}',policy);
 global_required:=(maximum->>'global')::boolean OR (predicates->>'global')::boolean;
 IF global_required IS NULL OR (proof->>'mode'='global') IS DISTINCT FROM global_required THEN
  RAISE EXCEPTION 'registration complete mutation classification changed' USING ERRCODE='P1034';END IF;
 SELECT coalesce(jsonb_agg(k ORDER BY k COLLATE "C"),'[]'::jsonb) INTO expected_accounts FROM jsonb_object_keys(maximum->'accounts') k;
 IF NOT global_required AND (expected_accounts='[]'::jsonb OR proof->'accounts' IS DISTINCT FROM expected_accounts) THEN
  RAISE EXCEPTION 'registration complete mutation accounts differ from admission' USING ERRCODE='P1034';END IF;
 -- Publication delete с хотя бы одним pointer выполнял SELECT FOR UPDATE,
 -- даже если actual fact отсутствует. Без pointer историческая ветвь не читает.
 SELECT coalesce(bool_or(value->'requires_update_acl'='true'::jsonb),false) INTO requires_update
  FROM jsonb_array_elements(program->'steps');
 IF requires_update AND NOT has_any_column_privilege((proof->>'invoker_oid')::oid,'kaname.relation_fact','UPDATE') THEN
  RAISE EXCEPTION 'publication fact row lock requires UPDATE privilege' USING ERRCODE='42501';END IF;
 SELECT * INTO STRICT epoch_result FROM kaname._authority_resource_epoch_wait_v2(maximum->'source_guards',policy,
  maximum->'binding_epochs',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+epoch_result.logical_rows;used_reads:=used_reads+epoch_result.logical_reads;
 IF action_value=1 THEN
  SELECT * INTO STRICT binding_result FROM kaname._authority_resource_registration_binding_wait_v2(certificate,program,p_reads-used_reads);
 ELSE SELECT '[]'::jsonb held_relations,'[]'::jsonb held_advisory,0 logical_reads INTO binding_result;END IF;
 used_reads:=used_reads+binding_result.logical_reads;
 SELECT * INTO STRICT current_result FROM kaname._authority_resource_required_reread_v2(source_index,required,
  sources->'write_keys',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+current_result.logical_rows;used_reads:=used_reads+current_result.logical_reads;
 IF current_result.predicate_protections IS DISTINCT FROM predicates->'protections' THEN
  RAISE EXCEPTION 'registration current predicate maximum changed' USING ERRCODE='P1034';END IF;
 SELECT * INTO STRICT authority_result FROM kaname._authority_resource_registration_authority_wait_v2(
  p_envelope,certificate,bundle_result.model_source,epoch_result.lock_witness,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+authority_result.logical_rows;used_reads:=used_reads+authority_result.logical_reads;
 audit_id:=NULL;
 IF program->'audit_required'='true'::jsonb THEN
  audit_id:=certificate->>'audit_id';
  IF audit_id IS NULL OR audit_id !~ '^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$' THEN
   RAISE EXCEPTION 'registration audit ID reservation missing' USING ERRCODE='42501';END IF;
  SELECT * INTO STRICT audit_result FROM kaname._authority_resource_audit_wait_v2(jsonb_build_object(audit_id,true),p_rows-used_rows,p_reads-used_reads);
 ELSE SELECT '[]'::jsonb lock_witness,0 logical_rows,0 logical_reads INTO audit_result;END IF;
 used_rows:=used_rows+audit_result.logical_rows;used_reads:=used_reads+audit_result.logical_reads;
 IF program->'reconcile_required'='true'::jsonb THEN
  SELECT * INTO STRICT reconcile_result FROM kaname._authority_resource_reconcile_wait_v2(1,p_reads-used_reads);
 ELSE SELECT '[]'::jsonb reserved_ids,'[]'::jsonb held_relations,'[]'::jsonb held_advisory,0 logical_reads INTO reconcile_result;END IF;
 used_reads:=used_reads+reconcile_result.logical_reads;
 operations:=(maximum->'operations')-'object_project_binding';
 IF operations='{}'::jsonb THEN SELECT '[]'::jsonb lock_witness,0 logical_reads INTO relation_result;
 ELSE
  SELECT * INTO STRICT relation_result FROM kaname._authority_resource_physical_relations_wait_v2(operations,p_reads-used_reads);
 END IF;
 used_reads:=used_reads+relation_result.logical_reads;
 reservations:=jsonb_build_object('audit_id',audit_id,'reconcile_ids',reconcile_result.reserved_ids);
 materialized:=kaname._authority_resource_registration_materialize_v2(certificate,maximum,sources,program,reservations,transaction_timestamp());
 held_relations:=relation_result.lock_witness||binding_result.held_relations||reconcile_result.held_relations;
 held_advisory:=(epoch_result.lock_witness->'held_advisory')||binding_result.held_advisory||audit_result.lock_witness||reconcile_result.held_advisory;
 IF used_rows>p_rows OR used_reads>p_reads THEN RAISE EXCEPTION 'registration aggregate prewait budget exceeded' USING ERRCODE='54000';END IF;
 compiled:=jsonb_build_object('intent',p_envelope->'intent','certificate',certificate,'sources',sources,'program',program,
  'authority',authority_result.authority,'body',materialized,'maximum',maximum,'epoch_witness',epoch_result.lock_witness,
  'catalog_rows',catalog_result.catalog_rows,'held_relations',held_relations,'held_advisory',held_advisory);
 PERFORM kaname._authority_resource_registration_store_v2(compiled);
 RETURN QUERY SELECT used_rows,used_reads;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_resource_unregistration_prepare_v2(p_envelope jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;source_index jsonb;verified jsonb;certificate jsonb;direct jsonb;plan jsonb;maximum jsonb;predicates jsonb;policy jsonb;
 current_state jsonb;reservations jsonb;body jsonb;compiled jsonb;required jsonb;operations jsonb;expected_accounts jsonb;expected_sources jsonb;
 audit_ids jsonb:='{}';audit_id text;key_value text;global_required boolean;source_required boolean;
 bundle_result record;catalog_result record;epoch_result record;current_result record;authority_result record;
 audit_result record;reconcile_result record;subject_result record;relation_result record;
 used_rows integer:=0;used_reads integer:=0;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource' OR proof->>'purpose' IS DISTINCT FROM 'participant'
 OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' NOT IN ('resource_pending','resource_source_pending')
 OR proof->>'consumer_finalized' IS DISTINCT FROM 'false' OR current_setting('transaction_isolation')<>'read committed'
 OR to_regclass('pg_temp.kaname_authority_resource_manifest') IS NOT NULL THEN
  RAISE EXCEPTION 'cleanup compiler requires fresh pending RC admission' USING ERRCODE='42501';END IF;
 IF p_rows IS NULL OR p_rows<1 OR p_rows>100000 OR p_reads IS NULL OR p_reads<1 OR p_reads>4096
 OR jsonb_typeof(p_envelope) IS DISTINCT FROM 'object' OR octet_length(p_envelope::text)>67108864
 OR p_envelope#>>'{intent,Action}' IS DISTINCT FROM '2' THEN
  RAISE EXCEPTION 'cleanup compiler input invalid' USING ERRCODE='42501';END IF;
 SELECT * INTO STRICT bundle_result FROM kaname._authority_resource_bundle_catalog_v2(p_rows,p_reads);
 used_rows:=used_rows+bundle_result.logical_rows;used_reads:=used_reads+bundle_result.logical_reads;
 SELECT * INTO STRICT catalog_result FROM kaname._authority_resource_catalog_wait_v2(p_envelope->'catalogs',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+catalog_result.logical_rows;used_reads:=used_reads+catalog_result.logical_reads;
 source_index:=kaname._authority_resource_capture_index_v2(p_envelope->'sources',100000);
 verified:=kaname._authority_resource_unregistration_certificate_v2(source_index,bundle_result.catalog,catalog_result.catalog_rows,p_envelope->'catalogs',p_envelope);
 certificate:=verified->'certificate';
 direct:=kaname._authority_resource_unregistration_direct_program_v2(source_index,verified,transaction_timestamp());
 plan:=kaname._authority_resource_unregistration_operation_maximum_v2(verified,direct);
 source_required:=plan->'source_effects'='true'::jsonb;
 IF (proof->>'consumer_profile'='resource_source_pending') IS DISTINCT FROM source_required THEN
  RAISE EXCEPTION 'cleanup SOURCE classification changed' USING ERRCODE='P1034';END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('kind',effect.kind,'id',effect.id) ORDER BY effect.kind COLLATE "C",effect.id COLLATE "C"),'[]'::jsonb)
 INTO expected_sources FROM (
  SELECT 'binding'::text kind,k id FROM jsonb_object_keys(verified->'changed_bindings') k
  UNION ALL SELECT 'role',k FROM jsonb_object_keys(verified->'changed_roles') k) effect;
 IF coalesce(nullif(p_envelope->'source_effects','null'::jsonb),'[]'::jsonb) IS DISTINCT FROM expected_sources THEN
  RAISE EXCEPTION 'cleanup SOURCE write census differs' USING ERRCODE='P1034';END IF;
 maximum:=kaname._authority_resource_unregistration_maximum_v2(source_index,verified,direct,catalog_result.catalog_rows,plan,p_envelope->'native_guards');
 required:=maximum->'required';predicates:=kaname._authority_resource_predicate_maximum_v2(source_index,required);
 policy:=(predicates->'policy_epochs')||(maximum->'policy_epochs');maximum:=jsonb_set(maximum,'{policy_epochs}',policy);
 global_required:=(maximum->>'global')::boolean OR (predicates->>'global')::boolean;
 IF global_required IS NULL OR (proof->>'mode'='global') IS DISTINCT FROM global_required THEN
  RAISE EXCEPTION 'cleanup complete mutation classification changed' USING ERRCODE='P1034';END IF;
 SELECT coalesce(jsonb_agg(q.key ORDER BY q.key COLLATE "C"),'[]'::jsonb) INTO expected_accounts FROM jsonb_object_keys(maximum->'accounts') q(key);
 IF NOT global_required AND (expected_accounts='[]'::jsonb OR proof->'accounts' IS DISTINCT FROM expected_accounts) THEN
  RAISE EXCEPTION 'cleanup complete mutation accounts changed' USING ERRCODE='P1034';END IF;
 SELECT * INTO STRICT epoch_result FROM kaname._authority_resource_epoch_wait_v2(maximum->'source_guards',policy,
  maximum->'binding_epochs',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+epoch_result.logical_rows;used_reads:=used_reads+epoch_result.logical_reads;
 SELECT * INTO STRICT current_result FROM kaname._authority_resource_required_reread_v2(source_index,required,
  maximum->'write_sources',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+current_result.logical_rows;used_reads:=used_reads+current_result.logical_reads;
 IF current_result.predicate_protections IS DISTINCT FROM predicates->'protections' THEN
  RAISE EXCEPTION 'cleanup current predicate maximum changed' USING ERRCODE='P1034';END IF;
 SELECT * INTO STRICT authority_result FROM kaname._authority_resource_registration_authority_wait_v2(
  p_envelope,certificate,bundle_result.model_source,epoch_result.lock_witness,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+authority_result.logical_rows;used_reads:=used_reads+authority_result.logical_reads;
 FOR audit_id IN SELECT jsonb_array_elements_text(verified->'withdrawal_audit_ids') LOOP
  audit_ids:=audit_ids||jsonb_build_object(audit_id,true);
 END LOOP;
 audit_id:=NULL;
 IF plan->'audit_possible'='true'::jsonb THEN
  audit_id:=certificate->>'audit_id';
  IF coalesce(audit_id,'') !~ '^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$' OR audit_ids ? audit_id THEN
   RAISE EXCEPTION 'cleanup root audit reservation invalid' USING ERRCODE='42501';END IF;
  audit_ids:=audit_ids||jsonb_build_object(audit_id,true);
 END IF;
 IF audit_ids<>'{}'::jsonb THEN
  SELECT * INTO STRICT audit_result FROM kaname._authority_resource_audit_capture_wait_v2(audit_ids,p_rows-used_rows,p_reads-used_reads,true);
 ELSE SELECT '[]'::jsonb lock_witness,0 logical_rows,0 logical_reads INTO audit_result;END IF;
 used_rows:=used_rows+audit_result.logical_rows;used_reads:=used_reads+audit_result.logical_reads;
 SELECT * INTO STRICT reconcile_result FROM kaname._authority_resource_reconcile_wait_v2((plan->>'reconcile_count')::integer,p_reads-used_reads);
 used_reads:=used_reads+reconcile_result.logical_reads;
 IF (verified->>'withdrawal_subject_count')::integer>0 THEN
  SELECT * INTO STRICT subject_result FROM kaname._authority_resource_subject_change_wait_v2((verified->>'withdrawal_subject_count')::integer,p_reads-used_reads);
 ELSE SELECT '[]'::jsonb reserved_ids,'[]'::jsonb held_relations,'[]'::jsonb held_advisory,0 logical_reads INTO subject_result;END IF;
 used_reads:=used_reads+subject_result.logical_reads;
 operations:=(maximum->'operations')-ARRAY['resource_reconcile_outbox','subject_change_outbox'];
 SELECT * INTO STRICT relation_result FROM kaname._authority_resource_physical_relations_capture_v2(operations,p_reads-used_reads,true);
 used_reads:=used_reads+relation_result.logical_reads;
 reservations:=jsonb_build_object('audit_id',audit_id,'audit_ids',verified->'withdrawal_audit_ids',
  'subject_ids',subject_result.reserved_ids,'reconcile_ids',reconcile_result.reserved_ids);
 current_state:=kaname._authority_resource_unregistration_current_v2(source_index,maximum,direct);
 body:=jsonb_build_object('source_index',source_index,'verified',verified,'catalog',bundle_result.catalog,'direct',direct,
  'maximum',maximum,'current',current_state,'reservations',reservations,'acl',relation_result.acl_capabilities);
 IF used_rows>p_rows OR used_reads>p_reads THEN RAISE EXCEPTION 'cleanup aggregate prewait exceeded' USING ERRCODE='54000';END IF;
 compiled:=jsonb_build_object('intent',p_envelope->'intent','certificate',certificate,'sources',jsonb_build_object('required',required),
  'program',plan,'authority',authority_result.authority,'body',body,'maximum',maximum,'epoch_witness',epoch_result.lock_witness,
  'catalog_rows',catalog_result.catalog_rows,
  'held_relations',relation_result.lock_witness||reconcile_result.held_relations||subject_result.held_relations,
  'held_advisory',(epoch_result.lock_witness->'held_advisory')||audit_result.lock_witness||reconcile_result.held_advisory||subject_result.held_advisory);
 PERFORM kaname._authority_resource_registration_store_v2(compiled);
 RETURN QUERY SELECT used_rows,used_reads;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_role_stage_epoch_lock(p_accounts text[],p_expected jsonb) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; actual jsonb; at_time timestamptz; sequence_id regclass;
BEGIN
 IF p_expected IS NULL OR pg_catalog.jsonb_typeof(p_expected)<>'object' THEN RAISE EXCEPTION 'binding epoch snapshot is absent' USING ERRCODE='40001'; END IF;
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL THEN RAISE EXCEPTION 'role stage requires signed entry' USING ERRCODE='42501'; END IF;
 IF proof->>'purpose' IS DISTINCT FROM 'decision' OR proof->>'kind' IS DISTINCT FROM 'role' THEN RAISE EXCEPTION 'role stage requires role decision' USING ERRCODE='42501'; END IF;
 IF proof->>'mode' IS DISTINCT FROM 'accounts' AND proof->>'mode' IS DISTINCT FROM 'global' THEN RAISE EXCEPTION 'invalid role stage coordinator mode' USING ERRCODE='42501'; END IF;
 IF p_accounts IS NULL THEN
  IF proof->>'mode' IS DISTINCT FROM 'global' THEN RAISE EXCEPTION 'binding global epoch requires global entry' USING ERRCODE='42501'; END IF;
 ELSE
  IF pg_catalog.cardinality(p_accounts)=0 OR EXISTS(SELECT 1 FROM pg_catalog.unnest(p_accounts) a WHERE a IS NULL OR a='') THEN RAISE EXCEPTION 'invalid binding epoch scope'; END IF;
  IF proof->>'mode'='accounts' AND (pg_catalog.jsonb_typeof(proof->'accounts') IS DISTINCT FROM 'array' OR NOT (proof->'accounts') @> pg_catalog.to_jsonb(p_accounts)) THEN RAISE EXCEPTION 'epoch accounts exceed role decision scope' USING ERRCODE='42501'; END IF;
 END IF;
 -- SELECT FOR UPDATE держит только ROW SHARE на таблице. SHARE blocker
 -- пережил бы row prelock и задержал DML уже после решения. Закрытый union
 -- actual Create/Update footprints берётся в одном порядке ДО final clock.
 -- Включены триггеры resource journal, policy/binding epochs и deferred
 -- carrier flush, а также ledger/outbox/fold; DML authority этим не выдаётся.
 LOCK TABLE kaname.access_binding_emitted_tuples,
   kaname.access_bindings,
   kaname.audit_outbox,
   kaname.authority_binding_epoch,
   kaname.authority_policy_carrier_pending,
   kaname.authority_policy_epoch,
   kaname.fga_outbox,
   kaname.relation_fact,
   kaname.resource_journal,
   kaname.resource_reconcile_outbox,
   kaname.role_bind_role_rule,
   kaname.role_create_binding_rule,
   kaname.role_rule_ref,
   kaname.role_rule_selectors,
   kaname.role_selector_verbs_pending,
   kaname.role_verb,
   kaname.roles IN ROW EXCLUSIVE MODE;
 -- У таблицы и её serial/identity sequence разные relation locks. nextval
 -- получает RowExclusiveLock sequence до конца TX и переносит ожидание
 -- ALTER SEQUENCE до final clock. Только закрытый actual union; никакого
 -- caller SQL, business DML или выдачи runtime прямых metadata privileges.
 -- Один номер на sequence на попытку допустимо пропускается (как rollback).
 -- Повторный epoch recheck не расходует номер: удерживаемый lock уже достаточен.
 FOREACH sequence_id IN ARRAY ARRAY[
   'kaname.fga_outbox_id_seq'::regclass,
   'kaname.resource_journal_sequence_no_seq'::regclass,
   'kaname.resource_reconcile_outbox_id_seq'::regclass
 ] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l
    WHERE l.pid=pg_catalog.pg_backend_pid() AND l.locktype='relation'
      AND l.relation=sequence_id AND l.mode='RowExclusiveLock' AND l.granted) THEN
   PERFORM pg_catalog.nextval(sequence_id);
  END IF;
 END LOOP;
 IF p_accounts IS NULL THEN
  PERFORM scope FROM kaname.authority_binding_epoch WHERE scope='' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'binding epochs are uninitialized' USING ERRCODE='40001'; END IF;
 ELSE
  PERFORM scope FROM kaname.authority_binding_epoch WHERE scope='' FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'binding epochs are uninitialized' USING ERRCODE='40001'; END IF;
  PERFORM scope FROM kaname.authority_binding_epoch WHERE scope=ANY(p_accounts) ORDER BY scope FOR SHARE;
  IF (SELECT count(*) FROM kaname.authority_binding_epoch WHERE scope=ANY(p_accounts))<>(SELECT count(DISTINCT a) FROM pg_catalog.unnest(p_accounts) a) THEN RAISE EXCEPTION 'binding epoch disappeared' USING ERRCODE='40001'; END IF;
 END IF;
 actual:=kaname.authority_binding_epoch_read(p_accounts);
 IF actual IS DISTINCT FROM p_expected THEN RAISE EXCEPTION 'binding stage changed' USING ERRCODE='40001'; END IF;
 at_time:=pg_catalog.clock_timestamp();
 UPDATE pg_temp.kaname_authority_attestation SET decision_at=at_time;
 RETURN at_time;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_metadata_preflight_v3(p_kind text,p_id text,p_rename boolean,p_audit text)
RETURNS TABLE(row_xmin text,row_value jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; table_name text; account_id text; sequence_id regclass;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'writer_contract' IS DISTINCT FROM '2'
 OR proof->>'purpose' IS DISTINCT FROM 'decision' OR proof->>'kind' IS DISTINCT FROM 'resource'
 OR p_id IS NULL OR p_id='' OR p_rename IS NULL OR p_audit IS NULL OR p_audit='' OR length(p_audit)>64 THEN
  RAISE EXCEPTION 'metadata preflight requires full resource decision entry' USING ERRCODE='42501';
 END IF;
 CASE p_kind WHEN 'account' THEN table_name:='accounts';
 WHEN 'project' THEN table_name:='projects';
 WHEN 'service_account' THEN table_name:='service_accounts';
 ELSE RAISE EXCEPTION 'unsupported metadata update' USING ERRCODE='22023'; END CASE;
 -- Вход уже удерживает полный набор account fences. Для project/service_account
 -- UNIQUE(account_id,name) не допускает конкурента того же ключа без того же
 -- exclusive account fence (либо GLOBAL); OLD/NEW scopes проверяет strict2 guard.
 -- Только глобально уникальное имя account требует дождаться чужого аккаунта
 -- через SRE. Description/labels и обе локальные rename-ветки берут RowExclusive.
 IF p_rename AND p_kind='account' THEN
  EXECUTE format('LOCK TABLE kaname.%I IN SHARE ROW EXCLUSIVE MODE',table_name);
 ELSE
  EXECUTE format('LOCK TABLE kaname.%I IN ROW EXCLUSIVE MODE',table_name);
 END IF;
 -- Complete direct/trigger write footprint: UPDATE target, policy+binding
 -- epochs, journal, audit and optional reconcile outbox. No tuple fold is
 -- executed by these metadata bodies; post-commit reconciliation is separate.
 LOCK TABLE kaname.audit_outbox,kaname.authority_binding_epoch,
  kaname.authority_policy_epoch,kaname.resource_journal,
  kaname.resource_reconcile_outbox IN ROW EXCLUSIVE MODE;
 FOREACH sequence_id IN ARRAY ARRAY['kaname.resource_journal_sequence_no_seq'::regclass,
  'kaname.resource_reconcile_outbox_id_seq'::regclass] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_backend_pid()
   AND l.locktype='relation' AND l.relation=sequence_id AND l.mode='RowExclusiveLock' AND l.granted) THEN
   PERFORM nextval(sequence_id);
  END IF;
 END LOOP;
 EXECUTE format('SELECT o.xmin::text,to_jsonb(o) FROM kaname.%I o WHERE id=$1 FOR UPDATE',table_name)
  INTO STRICT row_xmin,row_value USING p_id;
 account_id:=CASE WHEN p_kind='account' THEN row_value->>'id' ELSE row_value->>'account_id' END;
 IF account_id IS NULL OR account_id='' OR
  (proof->>'mode'='accounts' AND NOT (proof->'accounts' ? account_id)) THEN
  RAISE EXCEPTION 'metadata owner changed' USING ERRCODE='40001';
 END IF;
 -- The UPDATE's epoch trigger must not discover a new physical wait after
 -- the final clock. A missing epoch is an inconsistent stage, not an INSERT.
 PERFORM scope FROM kaname.authority_binding_epoch WHERE scope='' FOR KEY SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'binding root absent' USING ERRCODE='40001'; END IF;
 PERFORM scope FROM kaname.authority_binding_epoch WHERE scope=account_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'binding owner epoch absent' USING ERRCODE='40001'; END IF;
 PERFORM pg_advisory_xact_lock(1262569298,hashtext(p_audit));
 PERFORM id FROM kaname.audit_outbox WHERE id=p_audit FOR UPDATE;
 RETURN NEXT;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_sa_state_preflight_v3(p_id text,p_enabled boolean,p_audit text)
RETURNS TABLE(row_xmin text,row_value jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; account_id text; sequence_id regclass;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'writer_contract' IS DISTINCT FROM '2'
 OR proof->>'purpose' IS DISTINCT FROM 'decision' OR proof->>'kind' IS DISTINCT FROM 'resource'
 OR p_id IS NULL OR p_id='' OR p_enabled IS NULL OR p_audit IS NULL OR p_audit='' OR length(p_audit)>64 THEN
  RAISE EXCEPTION 'service account state preflight requires full decision entry' USING ERRCODE='42501';
 END IF;
 -- Тот же порядок, что у обычного UPDATE enabled: SA row раньше cutoff key.
 LOCK TABLE kaname.service_accounts IN ROW EXCLUSIVE MODE;
 SELECT o.xmin::text,to_jsonb(o) INTO STRICT row_xmin,row_value
 FROM kaname.service_accounts o WHERE id=p_id FOR UPDATE;
 account_id:=row_value->>'account_id';
 IF account_id IS NULL OR account_id='' OR
  (proof->>'mode'='accounts' AND NOT (proof->'accounts' ? account_id)) THEN
  RAISE EXCEPTION 'service account state owner changed' USING ERRCODE='40001';
 END IF;
 -- RowExclusive обязательно ДО key: иначе queued TRUNCATE создаёт обратное
 -- ребро к INSERT, который уже держит RowExclusive и ждёт наш key.
 LOCK TABLE kaname.minted_token_revocations IN ROW EXCLUSIVE MODE;
 PERFORM kaname._authority_minted_cutoff_key_v3(p_id);
 PERFORM subject FROM kaname.minted_token_revocations WHERE subject=p_id FOR UPDATE;
 -- Missing row защищена общим key даже от uncommitted INSERT обычного LOGIN.
 -- Никакой фиктивной отсечки или записи OLD до решения здесь нет.
 LOCK TABLE kaname.audit_outbox,kaname.authority_binding_epoch,
  kaname.authority_policy_epoch,kaname.resource_journal,
  kaname.resource_reconcile_outbox IN ROW EXCLUSIVE MODE;
 FOREACH sequence_id IN ARRAY ARRAY['kaname.resource_journal_sequence_no_seq'::regclass,
  'kaname.resource_reconcile_outbox_id_seq'::regclass] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_backend_pid()
   AND l.locktype='relation' AND l.relation=sequence_id AND l.mode='RowExclusiveLock' AND l.granted) THEN
   PERFORM nextval(sequence_id);
  END IF;
 END LOOP;
 PERFORM scope FROM kaname.authority_binding_epoch WHERE scope='' FOR KEY SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'binding root absent' USING ERRCODE='40001'; END IF;
 PERFORM scope FROM kaname.authority_binding_epoch WHERE scope=account_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'binding owner epoch absent' USING ERRCODE='40001'; END IF;
 PERFORM pg_advisory_xact_lock(1262569298,hashtext(p_audit));
 PERFORM id FROM kaname.audit_outbox WHERE id=p_audit FOR UPDATE;
 RETURN NEXT;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_full_contract_storage_v3() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE expected record; owner_oid oid; target text;
BEGIN
 SELECT relowner INTO owner_oid FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass;
 IF owner_oid IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=to_regclass('kaname.authority_writer_contract') AND relowner=owner_oid AND relkind='r' AND relpersistence='p')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
  WHERE c.oid=to_regclass('kaname.authority_writer_contract') AND a.grantee<>owner_oid) THEN RETURN false; END IF;
 FOR target IN SELECT unnest(kaname.authority_protocol_tables()) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=to_regclass('kaname.'||target)
   AND t.tgname='authority_protocol_statement' AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=62
   AND t.tgfoid='kaname.authority_protocol_statement_guard()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=to_regclass('kaname.'||target)
   AND t.tgname='authority_protocol_row' AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=31
   AND t.tgfoid='kaname.authority_protocol_row_guard()'::regprocedure) THEN RETURN false; END IF;
 END LOOP;
 -- Catalog invalidation is part of the full writer ABI: no early row close
 -- and no missed commit close. Check both pg_trigger and its constraint row.
 IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname._authority_protocol_catalog_changed_v3()'::regprocedure)<>6
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgfoid='kaname.authority_protocol_catalog_changed()'::regprocedure) THEN RETURN false; END IF;
 FOR target IN SELECT unnest(ARRAY['catalog_module','catalog_resource','catalog_verb']) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=to_regclass('kaname.'||target) AND c.relowner=owner_oid AND c.relkind='r' AND c.relpersistence='p') THEN RETURN false; END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_constraint c ON c.oid=t.tgconstraint
   WHERE t.tgrelid=to_regclass('kaname.'||target) AND t.tgname='authority_catalog_changed'
   AND t.tgfoid='kaname._authority_protocol_catalog_changed_v3()'::regprocedure
   AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=29
   AND t.tgdeferrable AND t.tginitdeferred AND t.tgnargs=0 AND t.tgqual IS NULL AND t.tgattr=''::int2vector
   AND c.contype='t' AND c.conname='authority_catalog_changed' AND c.conrelid=t.tgrelid AND c.condeferrable AND c.condeferred)
  OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t
   WHERE t.tgrelid=to_regclass('kaname.'||target) AND t.tgname='authority_catalog_truncated'
   AND t.tgfoid='kaname._authority_protocol_catalog_changed_v3()'::regprocedure
   AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=32 AND t.tgconstraint=0
   AND NOT t.tgdeferrable AND NOT t.tginitdeferred AND t.tgnargs=0 AND t.tgqual IS NULL)
  THEN RETURN false; END IF;
 END LOOP;
 -- Публичен только void-вход. PUBLIC, grant option и посторонний executor
 -- не являются частью approved runtime profile.
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.oid='kaname.authority_role_prelock_admit_v3()'::regprocedure
  AND a.grantee<>owner_oid AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE'
   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc e
    CROSS JOIN LATERAL aclexplode(coalesce(e.proacl,acldefault('f',e.proowner))) g
    WHERE e.oid='kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'::regprocedure
    AND g.grantee=a.grantee AND g.privilege_type='EXECUTE')))
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname.authority_role_prelock_admit_v3()'::regprocedure
  AND p.prorettype='void'::regtype AND p.provolatile='v'
  AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']) THEN RETURN false; END IF;
 -- Общий cutoff backstop принадлежит владельцу и действует на все INSERT/UPDATE.
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid='kaname.minted_token_revocations'::regclass
  AND relowner=owner_oid AND relkind='r' AND relpersistence='p')
 OR (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname._authority_minted_cutoff_order_v3()'::regprocedure)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid='kaname.minted_token_revocations'::regclass
  AND tgname='authority_minted_cutoff_order_v3' AND tgfoid='kaname._authority_minted_cutoff_order_v3()'::regprocedure
  AND tgenabled='O' AND NOT tgisinternal AND tgtype::integer=23 AND tgnargs=0 AND tgqual IS NULL
  AND tgattr=''::int2vector AND tgconstraint=0 AND NOT tgdeferrable AND NOT tginitdeferred)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.oid='kaname.authority_sa_state_preflight_v3(text,boolean,text)'::regprocedure AND a.grantee<>owner_oid
  AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR NOT EXISTS(
   SELECT 1 FROM pg_catalog.pg_proc e CROSS JOIN LATERAL aclexplode(e.proacl) g
   WHERE e.oid='kaname.authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)'::regprocedure
   AND g.grantee=a.grantee AND g.privilege_type='EXECUTE'))) THEN RETURN false; END IF;
 -- Публичен только void-вход. PUBLIC, grant option и посторонний executor
 -- не являются частью approved runtime profile.
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.oid='kaname.authority_parent_prelock_admit_v3()'::regprocedure
  AND a.grantee<>owner_oid AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE'
   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc e
    CROSS JOIN LATERAL aclexplode(coalesce(e.proacl,acldefault('f',e.proowner))) g
    WHERE e.oid='kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'::regprocedure
    AND g.grantee=a.grantee AND g.privilege_type='EXECUTE')))
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname.authority_parent_prelock_admit_v3()'::regprocedure
  AND p.prorettype='void'::regtype AND p.provolatile='v'
  AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']) THEN RETURN false; END IF;
 FOR expected IN SELECT * FROM (VALUES
 ('authority_parent_prelock_admit_v3()','0a5d8d81822501af40183c78d52e8897d3bf8583e8b888589a64951a88139247',true),
 ('_authority_minted_cutoff_key_v3(text)','e070405bfea920fb884831cd02890bd90810a65f4d617a828b1af9ea48542623',true),
 ('_authority_minted_cutoff_order_v3()','d911640bce1f00a365213aa03845461e4d6f479ca564e40745b810ad2976dd29',true),
 ('authority_sa_state_preflight_v3(text,boolean,text)','007c0ee49b9f8b53790462bb6089e3c4c6f07c2e1193d352b34066ee4b02434a',true),
 ('authority_role_prelock_admit_v3()','0a5d8d81822501af40183c78d52e8897d3bf8583e8b888589a64951a88139247',true),
 ('_authority_protocol_catalog_changed_v3()','974332f1dc2c6f42d12d35c49c89c201ac5deecf153f46070746ca0fcef6fbbb',true),
 ('authority_metadata_preflight_v3(text,text,boolean,text)','d18b70dce2a016c84b760463daca12ee698a1fbc9c0cb3a0e64bce9a7be7509e',true),
 ('_authority_protocol_enter_contract_v3(text,text[],jsonb,text,text,text,text,integer,text,integer)','1eae08ffff7b4eb936b224dfa08ed3e49679e968033a8e823e0bd3ef6d9786cf',true),
 ('_authority_consumer_enter_contract_v3(text,text[],jsonb,text,text,text,text,text,text,jsonb,integer)','7109bc396aeecee56a015a868826ebcf88bc15a050fceacf033b73971ff50aca',true),
 ('_authority_protocol_enter_v1_body(text,text[],jsonb,text,text,text,text,integer,text)','e71e29754a20d3a18054206600cf26cc6c234f26e798a41d9430177f612d68e4',true),
 ('_authority_protocol_enter_v2(text,text[],jsonb,text,text,text,text,text,text,jsonb)','e4a1ca86b280c64e7c9b5a54bbfb1e4152f59732f40c7f0748a5bb1a86fb77b1',true),
 ('_authority_protocol_attestation_v1_body()','944ba541d302f3d3d0ef2a3479ebeff637ec8ef0cb154134e15f16a9d5611b43',true),
 ('authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)','86ecf97ccb3cd5599f434955609fb3f1335dd82231f881deb510638981c8ec7a',true),
 ('authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)','33c57c5d0b23128b4fa5e694f4863073e7b6bcce4789c3cd98953285a991f1ea',true),
 ('authority_resource_enter_v3(text,text[],jsonb,text,text,text)','8e54f4da31fab3d4706a58039ea84de5ee88c8c258f92f73c65b7e098aebcc2d',true),
 ('authority_resource_source_enter_v3(text,text[],jsonb,text,text,text)','26f28ff899f445a4b2ca54c2d4ea4ac285fb0bf928082475fc862b1d6bddbd6a',true),
 ('authority_installation_enter_v3(text,text,text,text)','c9d988aa2dfb5851a95037d88ab9847da36ec8154507487bc962cc1b3c1f5b44',true),
 ('authority_full_contract_validate_v3(text,text,text)','25bfc4bd59d30c59e9246889a4279e1326b0ecbb5940b220fd52490a8777d1ea',true),
 ('authority_staged_contract_validate_v3()','0438c79b89809642700ab1d12a3dee84f8a0432c3b33589d47d16e8d9ce885b8',true),
 ('authority_protocol_stage_full_v3(text,bytea,text,text,text)','1f7a9c17af7a4c3ec041405fa9f0dddc69cdf3fa666ba72db47247cde8447037',false),
 ('authority_protocol_activate_full_v3(text,text,text)','646328a2433e1d31d17a9c178ac3ab59a5a65d8252accf5295a20d22705d31cf',false),
 ('authority_protocol_attestation()','08a5fa40928f579b763b6870192f241842145ef57b8889ecef0891768557f9ad',true),
 ('authority_protocol_statement_guard()','d22abfe60fef1cbdae8b23b0b5ebbaa3e4de29593d0fc6d75ec72145b9a1797c',true),
 ('authority_protocol_row_guard()','28a374ab14661c74d6922d400a085f4edf8c8da60269d0b478ac9112a3c08708',true),
 ('_authority_protocol_stage_generation1(text,bytea,text,text,text)','7ffb942af742bff4b556f07b00d9d8f75fefba3aa1f00445073140b5c8072bde',false),
 ('_authority_protocol_activate_generation1(text,text,text)','00d97c37e2ab533c232e4cffb975e8d71c3eefa98228e0f39d90249526bf041c',false),
 ('authority_protocol_drain()','f0e36bb29e96ba0417e9143821391b9df518541a017dcd9b171c037e167bc500',false),
 ('authority_protocol_require_drain()','61686507d75a6352d1f0fd97c9e3886c5c361af00778bdf3513693ee2dd6468b',false)
 ) AS pinned(signature,digest,definer) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('kaname.'||expected.signature)
   AND p.proowner=owner_oid AND p.prosecdef=expected.definer
   AND p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=expected.digest) THEN RETURN false; END IF;
  IF left(expected.signature,1)='_' AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
   WHERE p.oid=to_regprocedure('kaname.'||expected.signature) AND a.grantee<>owner_oid) THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_grant_runtime(p_runtime regrole) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE signature text; runtime_name text;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 PERFORM kaname._authority_protocol_grant_runtime_generation1(p_runtime);
 SELECT rolname INTO STRICT runtime_name FROM pg_catalog.pg_roles WHERE oid=p_runtime;
 FOREACH signature IN ARRAY ARRAY[
  'authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)',
  'authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)',
  'authority_resource_enter_v3(text,text[],jsonb,text,text,text)',
  'authority_resource_source_enter_v3(text,text[],jsonb,text,text,text)',
  'authority_installation_enter_v3(text,text,text,text)',
  'authority_full_contract_validate_v3(text,text,text)',
  'authority_staged_contract_validate_v3()',
  'authority_metadata_preflight_v3(text,text,boolean,text)',
  'authority_role_prelock_admit_v3()',
  'authority_parent_prelock_admit_v3()',
  'authority_sa_state_preflight_v3(text,boolean,text)'] LOOP
  EXECUTE format('GRANT EXECUTE ON FUNCTION kaname.%s TO %I',signature,runtime_name);
 END LOOP;
END $$;
-- +goose StatementEnd
DROP FUNCTION kaname._authority_crud_storage_v3();
DROP FUNCTION kaname.authority_crud_storage_v3();
DROP FUNCTION kaname.authority_scalar_sequence_finalize_v3();
DROP FUNCTION kaname.authority_sa_state_preflight_v4(text,boolean,text);
DROP FUNCTION kaname.authority_metadata_preflight_v4(text,text,boolean,text,jsonb);
DROP FUNCTION kaname._authority_scalar_journal_v3(text,text,jsonb,jsonb);
DROP FUNCTION kaname._authority_sa_state_preflight_body_v4(text,boolean,text);
DROP FUNCTION kaname.authority_role_sequence_stamp_v3(jsonb);
DROP FUNCTION kaname.authority_role_sequence_finalize_v3();
DROP FUNCTION kaname.authority_role_sequence_prepare_v3(jsonb,integer,integer);
DROP FUNCTION kaname._authority_resource_registration_sequence_final_v3(jsonb,timestamptz);
DROP FUNCTION kaname._authority_resource_registration_sequence_prepare_v3(jsonb,integer,integer);
DROP FUNCTION kaname._authority_resource_object_sequence_final_v3(jsonb,timestamptz);
DROP FUNCTION kaname._authority_resource_object_sequence_prepare_v3(jsonb,integer);
DROP FUNCTION kaname._authority_sequence_complete_v3();
DROP FUNCTION kaname._authority_sequence_applied_v3(text,bigint,jsonb);
DROP FUNCTION kaname._authority_sequence_claim_v3(text,jsonb,jsonb);
DROP FUNCTION kaname._authority_sequence_select_v3(integer[],timestamptz);
DROP FUNCTION kaname._authority_sequence_reserve_v3(text,jsonb,integer);
DROP FUNCTION kaname._authority_sequence_publish_v3(jsonb);
DROP FUNCTION kaname._authority_sequence_header_v3();
DROP FUNCTION kaname._authority_sequence_probe_v3();
DROP FUNCTION kaname._authority_protocol_snapshot_v3();
DROP FUNCTION kaname._authority_sequence_shape_v3();
DROP FUNCTION kaname._authority_sequence_store_v3();
DROP FUNCTION kaname._authority_sequence_excluded_v3(oid);
DROP FUNCTION kaname.authority_prepared_journal_value_v3(jsonb,jsonb);
DROP FUNCTION kaname.authority_sequence_origin_v3();
DROP FUNCTION kaname.authority_sequence_expectation_complete_v3();
DROP FUNCTION kaname._authority_sequence_expected_v3();
DROP FUNCTION kaname._authority_sequence_expect_v3(text);
DROP FUNCTION kaname.authority_sequence_program_completion_v3();
DROP FUNCTION kaname.authority_sequence_program_applied_v3();
DROP FUNCTION kaname.authority_fga_outbox_id_v3();
DROP FUNCTION kaname.authority_resource_journal_id_v3();
DROP FUNCTION kaname._authority_sequence_default_v3(text);
DROP FUNCTION kaname._authority_sequence_bind_v3(jsonb,timestamptz);
DROP FUNCTION kaname._authority_sequence_freeze_v3(jsonb);
DROP FUNCTION kaname._authority_metadata_preflight_body_v4(text,text,boolean,text);
DROP FUNCTION kaname.authority_cluster_admin_preflight_v4(text,text,text);
DROP FUNCTION kaname.authority_binding_withdrawal_sequence_finalize_v3();
DROP FUNCTION kaname.authority_binding_withdrawal_sequence_prepare_v3(text,text,text,integer,integer);
DROP FUNCTION kaname._authority_binding_stage_coordinates_v3(jsonb,text[],boolean,oid,integer,integer);
DROP FUNCTION kaname._authority_binding_stage_source_v3(jsonb,oid,integer);
DROP FUNCTION kaname.authority_binding_stage_sequence_finalize_v3(text);
DROP FUNCTION kaname.authority_binding_stage_sequence_prepare_v3(text,text[],jsonb,integer,integer);
DROP FUNCTION kaname._authority_binding_stage_snapshot_v3();
DROP FUNCTION kaname.authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer);
DROP FUNCTION kaname.authority_binding_insert_stamp_v3(text);
DROP FUNCTION kaname.authority_binding_sequence_finalize_v3();
DROP FUNCTION kaname.authority_binding_sequence_prepare_v3(text,jsonb);
DROP FUNCTION kaname._authority_binding_journal_v3(text,text,jsonb,jsonb,jsonb,integer);
DROP FUNCTION kaname._authority_binding_scope_tier_v3(text,jsonb,jsonb);
DROP FUNCTION kaname._authority_crud_write_metadata_v3(jsonb,jsonb,jsonb);
DROP FUNCTION kaname._authority_crud_json_keys_v3(jsonb);
DROP FUNCTION kaname._authority_crud_unique_wait_v3(text,jsonb,integer,integer);
DROP FUNCTION kaname._authority_crud_tuple_wait_v3(text,jsonb,boolean,integer,integer);
DROP FUNCTION kaname._authority_resource_crud_store_v3(jsonb);
DROP FUNCTION kaname._authority_crud_scope_capture_v3(jsonb,integer,integer);
DROP FUNCTION kaname._authority_crud_reserve_v3(jsonb,jsonb,jsonb,integer,integer);
DROP FUNCTION kaname._authority_crud_relation_wait_v3(jsonb,jsonb,jsonb,integer);
DROP FUNCTION kaname._authority_resource_crud_prepare_v3(jsonb,integer,integer);
DROP FUNCTION kaname._authority_crud_physical_v3(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz);
DROP FUNCTION kaname._authority_crud_pack_v3(jsonb,jsonb,jsonb);
DROP FUNCTION kaname._authority_crud_maximum_v3(jsonb,jsonb);
DROP FUNCTION kaname._authority_resource_crud_materialize_v3(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz);
DROP FUNCTION kaname._authority_crud_manifest_images_v3(jsonb,jsonb,jsonb,jsonb);
DROP FUNCTION kaname._authority_crud_lock_plan_v3(jsonb,jsonb,jsonb,timestamptz);
DROP FUNCTION kaname._authority_crud_lock_rows_v3(jsonb);
DROP FUNCTION kaname._authority_crud_key_maximum_v3(jsonb,jsonb,jsonb,jsonb,timestamptz);
DROP FUNCTION kaname.authority_crud_sequence_guard_v3();
DROP FUNCTION kaname._authority_crud_sequence_wait_v3(text,integer,integer);
DROP FUNCTION kaname.authority_crud_unique_guard_v3();
DROP FUNCTION kaname._authority_crud_unique_key_v3(text,jsonb);
DROP FUNCTION kaname._authority_crud_journal_rows_v3(jsonb,jsonb,timestamptz);
DROP FUNCTION kaname._authority_crud_journal_plan_v3(jsonb,jsonb,jsonb);
DROP FUNCTION kaname.authority_crud_journal_applied_v3();
DROP FUNCTION kaname.authority_resource_crud_journal_value_v3(jsonb,jsonb);
DROP FUNCTION kaname._authority_crud_journal_capture_v3(jsonb,jsonb,integer,integer);
DROP FUNCTION kaname._authority_crud_graph_index_v3(jsonb,jsonb,jsonb);
DROP FUNCTION kaname._authority_crud_fold_images_v3(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz);
DROP FUNCTION kaname._authority_crud_fold_capture_v3(jsonb,integer,integer);
DROP FUNCTION kaname.authority_crud_fga_id_applied_v3();
DROP FUNCTION kaname.authority_crud_fga_id_guard_v3();
DROP FUNCTION kaname._authority_crud_fga_rows_v3(jsonb,text,jsonb,integer,timestamptz);
DROP FUNCTION kaname._authority_crud_manifest_domain_v3(jsonb);
DROP FUNCTION kaname._authority_crud_intent_v3(jsonb);
DROP FUNCTION kaname._authority_crud_domain_images_v3(jsonb,jsonb,jsonb,timestamptz);
DROP FUNCTION kaname._authority_crud_image_v3(integer,text,text,jsonb,jsonb,boolean);
DROP FUNCTION kaname._authority_crud_command_plan_v3(jsonb,jsonb);
DROP FUNCTION kaname._authority_crud_structural_v3(text,text,text,text);
DROP FUNCTION kaname._authority_crud_command_v3(text,jsonb);
DROP FUNCTION kaname._authority_crud_require_completion_v3(jsonb);
DROP FUNCTION kaname.authority_resource_crud_lock_held_v3(text);
DROP FUNCTION kaname.authority_resource_crud_step_v3(text,jsonb);
DROP FUNCTION kaname._authority_crud_step_complete_v3(jsonb,integer);
DROP FUNCTION kaname.authority_resource_crud_body_values_v3();
DROP FUNCTION kaname._authority_crud_cascade_capture_v3(jsonb,integer,integer);
DROP FUNCTION kaname._authority_crud_capture_v3(jsonb,integer,integer);
DROP FUNCTION kaname._authority_crud_merge_tables_v3(jsonb,jsonb);
DROP FUNCTION kaname.authority_resource_crud_capture_v3(jsonb,integer,integer);
DROP FUNCTION kaname._authority_crud_aux_statement_v3();
DROP FUNCTION kaname._authority_crud_aux_images_v3(jsonb,jsonb,jsonb,timestamptz);
DROP FUNCTION kaname._authority_crud_aux_write_v3();
DROP FUNCTION kaname._authority_crud_aux_capture_v3(jsonb,jsonb,integer,integer);
DROP FUNCTION kaname._authority_crud_authority_graph_v3(jsonb,jsonb,integer,integer);
DROP FUNCTION kaname._authority_crud_anchor_capture_v3(jsonb,integer,integer);
