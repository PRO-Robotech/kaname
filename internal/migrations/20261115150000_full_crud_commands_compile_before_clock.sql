-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1034: семь закрытых команд Resource ABI, все ожидания до decision_at.
-- Приёмка: docs/engineering/acceptance/role-rights-stay-within-what-is-named.md
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
 -- Group Add не использует образы target members: свежая проверка
 -- программы сохраняется и отклоняет эту таблицу как другую семью мутаций.
 -- Последующие ветки ресурса и привязки сами получают точные образы строк.
 IF TG_TABLE_NAME<>'access_binding_target_members' THEN
  IF TG_OP<>'INSERT' THEN old_image:=to_jsonb(OLD);END IF;
  IF TG_OP<>'DELETE' THEN new_image:=to_jsonb(NEW);END IF;
 END IF;
 IF kaname._authority_group_add_row_v3(TG_TABLE_NAME,TG_OP,old_image,new_image) THEN
  IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
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
 IF proof IS NOT NULL AND proof->>'mode'='accounts' AND proof->>'kind'='binding' THEN
  IF TG_OP<>'INSERT' THEN old_image:=to_jsonb(OLD);END IF;
  IF TG_OP<>'DELETE' THEN new_image:=to_jsonb(NEW);END IF;
  IF kaname._authority_binding_mirror_before_write_v3(TG_TABLE_NAME,TG_OP,old_image,new_image) THEN
   IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
  END IF;
 END IF;
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
 IF kaname._authority_group_add_statement_v3(TG_TABLE_NAME,TG_OP) THEN RETURN NULL;END IF;
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
 IF manifest IS NULL THEN
  IF kaname._authority_binding_mirror_store_v3() IS NULL THEN RETURN false;END IF;
  expected:=jsonb_build_object('event_type',p_event_type,'payload',p_payload,'created_at',p_created_at);
  SELECT i.image_no,i.outbox_no INTO write_ordinal,selected FROM pg_temp.kaname_binding_mirror_images i
   WHERE i.table_name='fga_outbox' AND i.new_image=expected AND i.attempted AND i.consumed AND NOT i.folded
   ORDER BY i.command_no,i.image_no LIMIT 1;
  IF write_ordinal IS NULL THEN RAISE EXCEPTION 'binding mirror fold lacks actual journal' USING ERRCODE='42501';END IF;
  UPDATE pg_temp.kaname_binding_mirror_program SET active_outbox=selected WHERE singleton;
  invoker:=(kaname.authority_protocol_attestation()->>'invoker_oid')::oid;
  FOR image IN SELECT jsonb_build_object('operation',i.operation,'old',i.old_image,'new',i.new_image)
   FROM pg_temp.kaname_binding_mirror_images i WHERE i.table_name='relation_fact' AND i.outbox_no=selected ORDER BY i.image_no LOOP
   IF image->>'operation'='UPDATE' THEN CONTINUE;END IF;
   IF NOT has_table_privilege(invoker,'kaname.relation_fact','SELECT') THEN
    RAISE EXCEPTION 'binding mirror fold requires original SELECT ACL' USING ERRCODE='42501';END IF;
   IF image->>'operation'='INSERT' THEN
    IF NOT has_table_privilege(invoker,'kaname.relation_fact','INSERT') OR NOT has_table_privilege(invoker,'kaname.relation_fact','UPDATE') THEN
     RAISE EXCEPTION 'binding mirror fold requires original upsert ACL' USING ERRCODE='42501';END IF;
    row_value:=image->'new';
    INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject,source_version,created_at,condition_name,condition_params)
    VALUES(row_value->>'object_type',row_value->>'object_id',row_value->>'relation',row_value->>'subject',
     (row_value->>'source_version')::timestamptz,(row_value->>'created_at')::timestamptz,row_value->>'condition_name',row_value->'condition_params')
    ON CONFLICT(object_type,object_id,relation,subject) DO UPDATE
     SET source_version=EXCLUDED.source_version,condition_name=EXCLUDED.condition_name
     WHERE relation_fact.source_version<EXCLUDED.source_version;
   ELSE
    IF NOT has_table_privilege(invoker,'kaname.relation_fact','DELETE') OR NOT has_any_column_privilege(invoker,'kaname.relation_fact','UPDATE') THEN
     RAISE EXCEPTION 'binding mirror fold requires original delete ACL' USING ERRCODE='42501';END IF;
    row_value:=image->'old';
    DELETE FROM ONLY kaname.relation_fact WHERE object_type=row_value->>'object_type' AND object_id=row_value->>'object_id'
     AND relation=row_value->>'relation' AND subject=row_value->>'subject';
   END IF;
  END LOOP;
  UPDATE pg_temp.kaname_binding_mirror_program SET active_outbox=NULL WHERE singleton;
  UPDATE pg_temp.kaname_binding_mirror_images SET folded=true WHERE image_no=write_ordinal;
  RETURN true;
 END IF;
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
  -- Только положительный receipt точного allocation-only INSERT. Свежий proof
  -- выше сохранён; scalar DEFAULT и обе ветви UPDATE ниже не меняются.
  IF proof IS NULL AND TG_TABLE_NAME='fga_outbox'
   AND kaname._authority_forward_row_v4((new_key)::bigint,to_jsonb(NEW)-'id',false) THEN RETURN NEW;END IF;
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
 -- Один свежий proof/header на этот вызов. Probe сохраняет unsigned NULL
 -- и прежний порядок attestation перед owner/ACL/header проверками.
 SELECT q.proof,q.header INTO STRICT proof,sequence_program FROM kaname._authority_sequence_probe_v3() q;
 IF sequence_program#>>'{frozen,mode}'='authorize' THEN
  RAISE EXCEPTION 'authorization-only callback cannot mutate persistent state' USING ERRCODE='42501';
 END IF;
 IF kaname._authority_group_add_statement_v3(TG_TABLE_NAME,TG_OP) THEN RETURN NULL;END IF;
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
 -- В NULL-ветке producer выполнены только private consumer reads;
 -- ни DML, ни callback, ни изменение clock/identity между proof и проверкой нет.
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
DECLARE proof jsonb; consumer jsonb; storage oid; lock_mode text; snapshot record; strict_mode boolean; ignored_result boolean;
BEGIN
 -- Отсутствующий TEMP proof проверяем заново на каждом вызове, без SRF frame.
 -- Тот же свежий FOR SHARE и IF NOT: NULL enforcement не разрешает unsigned.
 IF to_regclass('pg_temp.kaname_authority_attestation') IS NULL THEN
  SELECT enforcement='strict' INTO STRICT strict_mode FROM kaname.authority_writer_protocol WHERE singleton FOR SHARE;
  IF NOT strict_mode THEN
   ignored_result := kaname._authority_compare_legacy_write_allowed_v2() IS NULL;
   ignored_result := pg_advisory_xact_lock(1262569292,0) IS NULL;
   RETURN NULL;
  END IF;
  RAISE EXCEPTION 'authority transaction attestation required' USING ERRCODE='42501';
 END IF;
 -- Present storage, включая пустое/повреждённое, идёт в прежний snapshot.
 -- Невалидная signed attestation здесь бросает ошибку; unsigned fallback нет.
 SELECT s.* INTO STRICT snapshot FROM kaname._authority_protocol_snapshot_v3() s;
 proof:=snapshot.proof;
 IF proof IS NULL THEN
  PERFORM kaname._authority_compare_legacy_write_allowed_v2();
  -- Compatibility RR/direct/maintenance writer должен войти до первой DML
  -- через общий BEFORE STATEMENT guard. NULL proof сохраняет unsigned admission.
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
 IF kaname.authority_protocol_attestation() IS NULL THEN RETURN NULL;END IF;
 program:=kaname._authority_sequence_store_v3();
 IF program IS NULL THEN RETURN NULL;END IF;
 IF program->>'family'<>'binding' OR program#>>'{frozen,mode}'<>'create'
 OR program#>>'{frozen,id}' IS DISTINCT FROM p_id OR jsonb_typeof(program->'selected') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'binding insert does not belong to selected create' USING ERRCODE='42501';END IF;
 RETURN (program#>>'{frozen,created_at}')::timestamptz;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Независимое чистое доказательство current+retained OLD scope для mirror.
-- Источники уже перечитаны owner с исходными SELECT правами вызывающего.
CREATE FUNCTION kaname._authority_binding_mirror_locality_v3(p_index jsonb,p_catalog jsonb,p_graph jsonb,p_binding jsonb,p_coordinate jsonb,p_ledger jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE typ text:=p_coordinate->>'type';identifier text:=p_coordinate->>'id';model text;matches integer;
 captured jsonb;state jsonb;data jsonb;accounts jsonb:=p_graph->'accounts';account_id text;
 command jsonb;item jsonb;tuple_value jsonb;exact_object text;local_scope boolean:=true;
BEGIN
 IF jsonb_typeof(accounts) IS DISTINCT FROM 'object' OR p_graph->>'object_type' IS DISTINCT FROM typ
 OR p_graph->>'object_id' IS DISTINCT FROM identifier OR p_binding->>'resource_type' IS DISTINCT FROM 'account'
 OR coalesce(typ,'')='' OR coalesce(identifier,'')='' THEN
  RAISE EXCEPTION 'binding mirror locality identity missing' USING ERRCODE='42501';END IF;
 SELECT count(*),min(r->>'ObjectType') INTO matches,model
 FROM jsonb_array_elements(coalesce(nullif(p_catalog#>'{Live,Resources}','null'::jsonb),'[]'::jsonb)) r
 WHERE (r->>'Module')||'.'||(r->>'Resource')=typ;
 IF matches=0 THEN RETURN false;END IF;
 IF matches<>1 OR coalesce(model,'')='' OR model~'[:#*[:space:][:cntrl:]]' OR length(model)>16384
 OR (SELECT count(*) FROM jsonb_array_elements(p_catalog#>'{Live,Resources}') r WHERE r->>'ObjectType'=model)<>1 THEN
  RAISE EXCEPTION 'binding mirror live mapping ambiguous' USING ERRCODE='42501';END IF;
 captured:=kaname._authority_resource_require_capture_v2(p_index,4,model,identifier);
 FOR state IN SELECT value FROM jsonb_array_elements(captured->'states') LOOP
  data:=state->2;account_id:=data->>'account_id';
  IF data->>'object_type' IS DISTINCT FROM model OR data->>'object_id' IS DISTINCT FROM identifier
  OR coalesce(account_id,'')='' OR account_id~'[:#*[:space:][:cntrl:]]' OR length(account_id)>16384
  OR (coalesce(data->>'project_id','')<>'' AND ((data->>'project_id')~'[:#*[:space:][:cntrl:]]' OR length(data->>'project_id')>16384)) THEN
   RAISE EXCEPTION 'binding retained scope linkage invalid' USING ERRCODE='42501';END IF;
  accounts:=accounts||jsonb_build_object(account_id,true);
 END LOOP;
 IF accounts='{}'::jsonb THEN RAISE EXCEPTION 'binding mirror owner absent' USING ERRCODE='42501';END IF;
 FOR account_id IN SELECT jsonb_object_keys(accounts) LOOP
  IF coalesce(account_id,'')='' OR account_id~'[:#*[:space:][:cntrl:]]' OR length(account_id)>16384 THEN
   RAISE EXCEPTION 'binding mirror account identity invalid' USING ERRCODE='42501';END IF;
  captured:=kaname._authority_resource_require_capture_v2(p_index,23,'account',account_id);
  IF jsonb_array_length(captured->'states')<>1 OR captured->'states'->0->2->>'id' IS DISTINCT FROM account_id THEN
   RAISE EXCEPTION 'binding mirror account source absent' USING ERRCODE='42501';END IF;
  IF account_id IS DISTINCT FROM p_binding->>'resource_id' THEN local_scope:=false;END IF;
 END LOOP;
 exact_object:=model||':'||identifier;
 -- OLD claims не доказывают владение чужим адресом. Такой подлинный старый
 -- ledger сохраняет GLOBAL; forged commands отсекают исходные obligations.
 FOR item IN SELECT value FROM jsonb_array_elements(p_ledger) LOOP
  IF item->>'object' IS DISTINCT FROM exact_object THEN local_scope:=false;END IF;
 END LOOP;
 FOR item IN SELECT value FROM jsonb_array_elements(p_coordinate->'desired') LOOP
  FOR tuple_value IN SELECT value FROM jsonb_array_elements(coalesce(nullif(item->'Tuples','null'::jsonb),'[]'::jsonb)) LOOP
   IF tuple_value->>'Object' IS DISTINCT FROM exact_object THEN local_scope:=false;END IF;
  END LOOP;
 END LOOP;
 FOR command IN SELECT value FROM jsonb_array_elements(p_coordinate->'commands') LOOP
  FOR tuple_value IN
   SELECT value FROM jsonb_array_elements(coalesce(nullif(command->'Tuples','null'::jsonb),'[]'::jsonb))
   UNION ALL SELECT value->'Tuple' FROM jsonb_array_elements(coalesce(nullif(command->'Refs','null'::jsonb),'[]'::jsonb))
   UNION ALL SELECT value->'Tuple' FROM jsonb_array_elements(coalesce(nullif(command->'Rows','null'::jsonb),'[]'::jsonb)) LOOP
   IF tuple_value->>'Object' IS DISTINCT FROM exact_object THEN local_scope:=false;END IF;
  END LOOP;
 END LOOP;
 RETURN local_scope;
END $$;

-- Закрытые записи принадлежат owner, связаны с nonce текущего RC и не
-- принимают caller scope. Хеш служит индексом; OLD/NEW сравниваются целиком.
CREATE FUNCTION kaname._authority_binding_mirror_store_v3() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;owner_oid oid;relation_id oid;result jsonb;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind'<>'binding' OR proof->>'purpose'<>'participant' THEN RETURN NULL;END IF;
 IF to_regclass('pg_temp.kaname_binding_mirror_program') IS NULL THEN RETURN NULL;END IF;
 SELECT oid INTO STRICT owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
 FOREACH relation_id IN ARRAY ARRAY[to_regclass('pg_temp.kaname_binding_mirror_program'),to_regclass('pg_temp.kaname_binding_mirror_images'),to_regclass('pg_temp.kaname_binding_mirror_policy_receipt')] LOOP
  IF relation_id IS NULL OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=relation_id
   AND c.relowner=owner_oid AND c.relpersistence='t' AND c.relkind='r')
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
   WHERE c.oid=relation_id AND a.grantee<>owner_oid) THEN
   RAISE EXCEPTION 'untrusted binding mirror program' USING ERRCODE='42501';END IF;
 END LOOP;
 -- Горячая проверка не читает frozen sources или полный массив images.
 SELECT jsonb_build_object('backend',p.backend,'transaction_id',p.transaction_id,'invoker_oid',p.invoker_oid,
  'nonce',p.nonce,'binding',p.binding_id,'accounts',p.accounts,'epochs',p.epochs,'epoch_clock',p.epoch_clock,
  'final_clock',p.final_clock,'image_limit',p.image_limit) INTO STRICT result FROM pg_temp.kaname_binding_mirror_program p WHERE singleton;
 IF result->>'backend' IS DISTINCT FROM proof->>'backend' OR result->>'transaction_id' IS DISTINCT FROM proof->>'transaction_id'
 OR result->>'invoker_oid' IS DISTINCT FROM proof->>'invoker_oid' OR result->>'nonce' IS DISTINCT FROM proof->>'nonce'
 OR proof->>'mode' IS DISTINCT FROM 'accounts' OR result->'accounts' IS DISTINCT FROM proof->'accounts' THEN
  RAISE EXCEPTION 'binding mirror program identity changed' USING ERRCODE='42501';END IF;
 RETURN result;
END $$;


-- Audit не является новым authority admission. Чистый либо повторно взятый
-- из пула ordinary backend не должен брать compatibility fence после users row.
-- Signed/compare witness проверяется прежним getter; DISCARD TEMP не стирает
-- xact root lock, поэтому исчезнувший witness не переводит такую TX в ordinary.
CREATE FUNCTION kaname._authority_audit_binding_store_v3() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE storage oid;name text;populated boolean;owner_oid oid;
BEGIN
 SELECT oid INTO STRICT owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
 FOREACH name IN ARRAY ARRAY['kaname_authority_attestation','kaname_authority_compare'] LOOP
  storage:=to_regclass(format('pg_temp.%I',name));
  IF storage IS NULL THEN CONTINUE;END IF;
  -- Не читаем caller-owned таблицу/VIEW даже когда она объявляет себя пустой.
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=storage
   AND relowner=owner_oid AND relpersistence='t' AND relkind='r') THEN
   RAISE EXCEPTION 'untrusted audit authority storage' USING ERRCODE='42501';END IF;
  EXECUTE format('SELECT EXISTS(SELECT 1 FROM pg_temp.%I)',name) INTO populated;
  IF populated THEN RETURN kaname._authority_binding_mirror_store_v3();END IF;
 END LOOP;
 -- Обе формы successful entry держат один root key до конца TX. Session
 -- unlock и DISCARD TEMP его не снимают; rollback до entry отменяет и эффекты.
 IF to_regclass('pg_temp.kaname_binding_mirror_program') IS NOT NULL
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_backend_pid()
  AND l.database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
  AND l.locktype='advisory' AND l.classid=1262569283::oid AND l.objid=0::oid
  AND l.objsubid=2 AND l.mode IN ('ShareLock','ExclusiveLock') AND l.granted) THEN
  RAISE EXCEPTION 'audit authority witness disappeared' USING ERRCODE='42501';END IF;
 RETURN NULL;
END $$;

-- Квитанция создаётся только после неизменных actual epoch locks и сравнения
-- поколений. Она не заменяет locks и не допускает другой clock refresher.
CREATE FUNCTION kaname._authority_binding_mirror_epoch_v3(p_accounts text[],p_epochs jsonb,p_at timestamptz) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;snapshot jsonb;program jsonb;owner_oid oid;storage oid;has_mirror boolean;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof->>'kind' IS DISTINCT FROM 'binding' OR to_regclass('pg_temp.kaname_binding_sequence_snapshot') IS NULL THEN RETURN;END IF;
 storage:='pg_temp.kaname_binding_sequence_snapshot'::regclass;
 SELECT oid INTO STRICT owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=storage AND c.relowner=owner_oid AND c.relpersistence='t' AND c.relkind='r')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
  WHERE c.oid=storage AND a.grantee<>owner_oid) THEN RAISE EXCEPTION 'untrusted binding epoch receipt storage' USING ERRCODE='42501';END IF;
 SELECT s.mirror IS NOT NULL INTO STRICT has_mirror FROM pg_temp.kaname_binding_sequence_snapshot s WHERE singleton;
 IF NOT has_mirror THEN RETURN;END IF;
 snapshot:=kaname._authority_binding_stage_snapshot_v3();
 IF snapshot->'accounts' IS DISTINCT FROM to_jsonb(p_accounts) OR snapshot->'epochs' IS DISTINCT FROM p_epochs
 OR proof->'accounts' IS DISTINCT FROM to_jsonb(p_accounts) OR proof->>'mode' IS DISTINCT FROM 'accounts'
 OR p_at IS DISTINCT FROM (proof->>'decision_at')::timestamptz THEN
  RAISE EXCEPTION 'binding mirror epoch receipt differs' USING ERRCODE='42501';END IF;
 -- После Binding ROW locks разрешена только проверка уже удерживаемой квитанции.
 -- Отсутствующий early receipt не может открыть прежний поздний acquire путь.
 IF to_regclass('pg_temp.kaname_binding_mirror_policy_receipt') IS NULL THEN
  RAISE EXCEPTION 'binding policy receipt missing before epoch recheck' USING ERRCODE='42501';END IF;
 PERFORM kaname._authority_binding_mirror_policy_prepare_v3(snapshot);
 UPDATE pg_temp.kaname_binding_sequence_snapshot SET locked_xid=proof->>'transaction_id',locked_at=p_at WHERE singleton;
 program:=kaname._authority_binding_mirror_store_v3();
 IF program IS NOT NULL THEN
  IF program->'epochs' IS DISTINCT FROM p_epochs OR program->>'binding' IS DISTINCT FROM snapshot->>'binding_id'
  OR program->>'final_clock' IS NOT NULL THEN RAISE EXCEPTION 'binding mirror epoch receipt repeated after finalization' USING ERRCODE='42501';END IF;
  UPDATE pg_temp.kaname_binding_mirror_program SET epoch_clock=p_at WHERE singleton;
 END IF;
END $$;

-- Подготовка после прежнего prelockBindingCommands. Все шесть реальных
-- fold SELECT используют остаток общего бюджета, исходные SELECT ACL и RC.
CREATE FUNCTION kaname._authority_binding_mirror_prepare_v3(p_snapshot jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;mirror jsonb;commands jsonb;fold_program jsonb;sources jsonb;physical jsonb;image_limit integer;
 owner_oid oid;grantee record;table_name text;relation_id oid;used_rows integer;used_reads integer;audit_command jsonb;audit_key text;audit_id text;audit_tenant text;
 audit_ids jsonb:='{}';audit_plan jsonb:='{}';audit_rows jsonb:='{}';audit_part record;audit_lock record;audit_present boolean;ordinal integer:=0;policy_read_cost integer;policy_row_cost integer;policy_keys text[];policy_key text;
BEGIN
 mirror:=p_snapshot->'mirror';
 IF mirror IS NULL OR mirror='null'::jsonb THEN RETURN QUERY SELECT 0,0;RETURN;END IF;
 proof:=kaname.authority_protocol_attestation();
 IF p_snapshot IS DISTINCT FROM kaname._authority_binding_stage_snapshot_v3()
 OR p_snapshot->>'locked_xid' IS DISTINCT FROM proof->>'transaction_id'
 OR p_snapshot->>'locked_at' IS DISTINCT FROM proof->>'decision_at'
 OR proof->>'mode' IS DISTINCT FROM 'accounts' OR p_snapshot->'accounts' IS DISTINCT FROM proof->'accounts'
 OR p_rows IS NULL OR p_rows<0 OR p_rows>100000 OR p_reads IS NULL OR p_reads<0 OR p_reads>4096
 OR to_regclass('pg_temp.kaname_binding_mirror_program') IS NOT NULL OR to_regclass('pg_temp.kaname_binding_mirror_images') IS NOT NULL THEN
  RAISE EXCEPTION 'binding mirror prepare lacks exact held epoch witness' USING ERRCODE='42501';END IF;
 commands:=mirror->'commands';
 SELECT jsonb_build_object('commands',coalesce(jsonb_agg(jsonb_build_object('kind',CASE WHEN c->>'Kind' IN ('write','delete')
  THEN 'fga.tuple.'||(c->>'Kind') ELSE 'binding.domain' END,'request',coalesce(nullif(c->'Tuples','null'::jsonb),'[]'::jsonb)) ORDER BY n),'[]'::jsonb))
 INTO fold_program FROM jsonb_array_elements(commands) WITH ORDINALITY q(c,n);
 FOREACH table_name IN ARRAY ARRAY['relation_fact','access_binding_emitted_tuples','resource_registration_pointer',
  'resource_registration_retirement','cluster_admin_grants','access_bindings'] LOOP
  IF NOT has_table_privilege((proof->>'invoker_oid')::oid,('kaname.'||table_name)::regclass,'SELECT') THEN
   RAISE EXCEPTION 'binding mirror fold requires original SELECT privileges' USING ERRCODE='42501';END IF;
 END LOOP;
 SELECT r.logical_reads,r.logical_rows INTO STRICT policy_read_cost,policy_row_cost FROM pg_temp.kaname_binding_mirror_policy_receipt r WHERE r.singleton;
 sources:=kaname._authority_crud_fold_capture_v3(fold_program,p_rows-policy_row_cost,p_reads-policy_read_cost);
 -- Новый собственный claim может не иметь OLD ledger. Его carrier уже
 -- перечитан в RR и защищён неизменными epoch/row locks; новое SQL не нужно.
 IF sources->'bindings' ? (p_snapshot->>'binding_id') AND sources->'bindings'->(p_snapshot->>'binding_id') IS DISTINCT FROM mirror->'binding' THEN
  RAISE EXCEPTION 'binding mirror carrier changed under epoch witness' USING ERRCODE='P1034';END IF;
 sources:=jsonb_set(sources,'{bindings}',(sources->'bindings')||jsonb_build_object(p_snapshot->>'binding_id',mirror->'binding'));
 used_rows:=(sources->>'logical_rows')::integer+policy_row_cost;used_reads:=(sources->>'logical_reads')::integer+policy_read_cost;
 -- Audit присутствует в том же stream. Tenant/ID и UNIQUE wait готовятся до clock.
 FOR audit_command IN SELECT value FROM jsonb_array_elements(commands) LOOP
  ordinal:=ordinal+1;
  IF audit_command->>'Kind'<>'audit' THEN CONTINUE;END IF;
  IF NOT has_table_privilege((proof->>'invoker_oid')::oid,'kaname.audit_outbox','INSERT') THEN
   RAISE EXCEPTION 'binding audit requires original INSERT ACL' USING ERRCODE='42501';END IF;
  audit_tenant:=NULL;
  IF audit_command#>>'{Scope,Type}'='account' THEN audit_tenant:=nullif(audit_command#>>'{Scope,ID}','');
  ELSIF audit_command#>>'{Scope,Type}'='project' THEN
   IF NOT has_table_privilege((proof->>'invoker_oid')::oid,'kaname.projects','SELECT') THEN
    RAISE EXCEPTION 'binding audit requires original project SELECT ACL' USING ERRCODE='42501';END IF;
   used_reads:=used_reads+1;IF used_reads>p_reads THEN RAISE EXCEPTION 'binding audit read budget exceeded' USING ERRCODE='54000';END IF;
   SELECT account_id INTO audit_tenant FROM kaname.projects WHERE id=audit_command#>>'{Scope,ID}' FOR KEY SHARE;
   IF FOUND THEN used_rows:=used_rows+1;END IF;
  END IF;
  audit_id:='evt_'||substr(replace(gen_random_uuid()::text,'-',''),1,22);
  IF audit_ids ? audit_id THEN RAISE EXCEPTION 'binding audit random ID repeated' USING ERRCODE='P1034';END IF;
  audit_ids:=audit_ids||jsonb_build_object(audit_id,true);
  audit_key:=jsonb_build_array(audit_command->>'Binding',audit_command#>>'{Member,ObjectType}',audit_command#>>'{Member,ObjectID}',
   audit_command#>>'{Scope,Type}',audit_command#>>'{Scope,ID}')::text;
  audit_plan:=audit_plan||jsonb_build_object(audit_key,coalesce(audit_plan->audit_key,'[]'::jsonb)||
   jsonb_build_array(jsonb_build_object('id',audit_id,'tenant_account_id',audit_tenant)));
 END LOOP;
 IF audit_ids<>'{}'::jsonb THEN
  LOCK TABLE kaname.audit_outbox IN ROW EXCLUSIVE MODE;
  FOR audit_lock IN SELECT DISTINCT hashtext(k) h FROM jsonb_object_keys(audit_ids) k ORDER BY h LOOP
   PERFORM pg_advisory_xact_lock(1262569298,audit_lock.h);
  END LOOP;
  FOR audit_id IN SELECT k FROM jsonb_object_keys(audit_ids) k ORDER BY k COLLATE "C" LOOP
   used_reads:=used_reads+1;IF used_reads>p_reads THEN RAISE EXCEPTION 'binding audit reservation read budget exceeded' USING ERRCODE='54000';END IF;
   SELECT true INTO audit_present FROM kaname.audit_outbox a WHERE a.id=audit_id FOR UPDATE;
   IF coalesce(audit_present,false) THEN RAISE EXCEPTION 'binding reserved audit ID already exists' USING ERRCODE='P1034';END IF;
  END LOOP;
 END IF;
 physical:=kaname._authority_resource_object_physical_v2(commands,mirror->'members',mirror->'ledger',audit_plan,
  transaction_timestamp(),(proof->>'decision_at')::timestamptz);
 SELECT ARRAY(SELECT jsonb_array_elements_text(r.keys)),r.logical_reads,r.logical_rows
 INTO policy_keys,policy_read_cost,policy_row_cost FROM pg_temp.kaname_binding_mirror_policy_receipt r WHERE singleton;
 IF policy_keys IS NULL OR used_reads>p_reads OR used_rows>p_rows THEN
  RAISE EXCEPTION 'binding mirror early policy receipt budget exceeded' USING ERRCODE='54000';END IF;
 -- Верхняя граница включает оба BEFORE images для каждого fact upsert.
 -- Это work charge, а не объявление фиктивных SELECT или changed rows.
 SELECT jsonb_array_length(physical->'images')+jsonb_array_length(physical->'audits')+2*coalesce(sum(jsonb_array_length(coalesce(nullif(c->'Tuples','null'::jsonb),'[]'::jsonb))),0)
 INTO image_limit FROM jsonb_array_elements(commands) c;
 IF image_limit>100000 OR used_rows+image_limit>p_rows THEN
  RAISE EXCEPTION 'binding mirror image work budget exceeded' USING ERRCODE='54000';END IF;
 CREATE TEMP TABLE kaname_binding_mirror_program(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
  backend integer NOT NULL,transaction_id text NOT NULL,invoker_oid oid NOT NULL,nonce text NOT NULL,binding_id text NOT NULL,
  accounts jsonb NOT NULL,epochs jsonb NOT NULL,epoch_clock timestamptz NOT NULL,final_clock timestamptz,
  image_limit integer NOT NULL,frozen jsonb NOT NULL,policy_keys jsonb NOT NULL,active_outbox integer,commands jsonb NOT NULL,
  next_command integer NOT NULL DEFAULT 1,active_command integer,audit_rows jsonb NOT NULL DEFAULT '{}'::jsonb) ON COMMIT DROP;
 CREATE TEMP TABLE kaname_binding_mirror_images(image_no integer PRIMARY KEY,table_name text NOT NULL,operation text NOT NULL,
  image_hash bytea NOT NULL,old_hash bytea,new_hash bytea,old_image jsonb,new_image jsonb,
  command_no integer NOT NULL,origin jsonb NOT NULL,required boolean NOT NULL,
  attempted boolean NOT NULL DEFAULT false,consumed boolean NOT NULL DEFAULT false,
  outbox_no integer,folded boolean NOT NULL DEFAULT false,epoch_keys jsonb) ON COMMIT DROP;
 CREATE INDEX kaname_binding_mirror_obligations ON kaname_binding_mirror_images(command_no) WHERE required AND NOT consumed;
 CREATE INDEX kaname_binding_mirror_image_key ON kaname_binding_mirror_images(table_name,operation,image_hash);
 CREATE INDEX kaname_binding_mirror_old_key ON kaname_binding_mirror_images(table_name,old_hash);
 CREATE INDEX kaname_binding_mirror_new_key ON kaname_binding_mirror_images(table_name,new_hash);
 SELECT oid INTO STRICT owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
 FOREACH relation_id IN ARRAY ARRAY['pg_temp.kaname_binding_mirror_program'::regclass,'pg_temp.kaname_binding_mirror_images'::regclass] LOOP
  EXECUTE format('REVOKE ALL ON %s FROM PUBLIC',relation_id::regclass);
  FOR grantee IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE c.oid=relation_id AND a.grantee<>owner_oid LOOP
   EXECUTE format('REVOKE ALL ON %s FROM %I',relation_id::regclass,grantee.rolname);
  END LOOP;
 END LOOP;
 INSERT INTO pg_temp.kaname_binding_mirror_program(backend,transaction_id,invoker_oid,nonce,binding_id,accounts,epochs,epoch_clock,image_limit,frozen,policy_keys,commands)
 VALUES((proof->>'backend')::integer,proof->>'transaction_id',(proof->>'invoker_oid')::oid,proof->>'nonce',p_snapshot->>'binding_id',
  proof->'accounts',p_snapshot->'epochs',(proof->>'decision_at')::timestamptz,image_limit,
  jsonb_build_object('mirror',mirror,'fold_program',fold_program,'sources',sources,'tx_at',transaction_timestamp(),'audit_plan',audit_plan),to_jsonb(policy_keys),commands);
 used_reads:=used_reads+2*jsonb_array_length(commands)+(SELECT count(*) FROM jsonb_object_keys(audit_ids));
 IF used_reads>p_reads THEN RAISE EXCEPTION 'binding command lifecycle read budget exceeded' USING ERRCODE='54000';END IF;
 RETURN QUERY SELECT used_rows+image_limit,used_reads;
END $$;

-- После окончательных часов только чистые previously bounded images.
-- Никаких новых scope/source reads, locks или reserved IDs здесь нет.
CREATE FUNCTION kaname._authority_binding_mirror_finalize_v3(p_binding text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE metadata jsonb;program jsonb;frozen jsonb;physical jsonb;folded jsonb;images jsonb;at_time timestamptz;proof jsonb;
BEGIN
 metadata:=kaname._authority_binding_mirror_store_v3();IF metadata IS NULL THEN RETURN;END IF;
 proof:=kaname.authority_protocol_attestation();program:=kaname._authority_sequence_store_v3();
 at_time:=(proof->>'decision_at')::timestamptz;
 IF metadata->>'binding' IS DISTINCT FROM p_binding OR metadata->>'final_clock' IS NOT NULL
 OR metadata->>'epoch_clock' IS DISTINCT FROM proof->>'decision_at'
 OR program#>>'{frozen,kind}' IS DISTINCT FROM 'binding.stage' OR program#>>'{frozen,binding}' IS DISTINCT FROM p_binding
 OR program->>'decision_at' IS DISTINCT FROM proof->>'decision_at' OR program->'selected'='null'::jsonb THEN
  RAISE EXCEPTION 'binding mirror finalization lacks final epoch/sequence witness' USING ERRCODE='42501';END IF;
 images:='[]'::jsonb;
 IF program#>>'{frozen,expires_at}' IS NOT NULL AND (program#>>'{frozen,expires_at}')::timestamptz<=at_time THEN
  UPDATE pg_temp.kaname_binding_mirror_program SET commands='[]'::jsonb WHERE singleton;
 END IF;
 IF program#>>'{frozen,expires_at}' IS NULL OR (program#>>'{frozen,expires_at}')::timestamptz>at_time THEN
  SELECT p.frozen INTO STRICT frozen FROM pg_temp.kaname_binding_mirror_program p WHERE singleton;
  physical:=kaname._authority_resource_object_physical_v2(frozen#>'{mirror,commands}',frozen#>'{mirror,members}',
   frozen#>'{mirror,ledger}',frozen->'audit_plan',(frozen->>'tx_at')::timestamptz,at_time);
  folded:=kaname._authority_crud_fold_images_v3(frozen->'fold_program',physical->'images',physical->'outboxes',
   frozen->'sources',(frozen->>'tx_at')::timestamptz,at_time);
  SELECT coalesce(jsonb_agg(i||CASE WHEN i->>'table'='fga_outbox' THEN jsonb_build_object('outbox',
   outbox_number) ELSE '{}'::jsonb END ORDER BY n),'[]'::jsonb)
 INTO images FROM (SELECT i,n,count(*) FILTER (WHERE i->>'table'='fga_outbox') OVER (ORDER BY n) AS outbox_number
  FROM jsonb_array_elements(physical->'images') WITH ORDINALITY q(i,n)) numbered;
 images:=images||(folded->'images');
 SELECT coalesce(jsonb_object_agg(a->>'command',a->'row'),'{}'::jsonb) INTO physical FROM jsonb_array_elements(physical->'audits') a;
 UPDATE pg_temp.kaname_binding_mirror_program SET audit_rows=physical WHERE singleton;
 END IF;
 IF jsonb_array_length(images)>(metadata->>'image_limit')::integer THEN
  RAISE EXCEPTION 'binding mirror final images exceed prepared maximum' USING ERRCODE='54000';END IF;
 INSERT INTO pg_temp.kaname_binding_mirror_images(image_no,table_name,operation,image_hash,old_hash,new_hash,old_image,new_image,command_no,origin,required,outbox_no)
 SELECT n::integer,i->>'table',i->>'operation',sha256(convert_to(jsonb_build_array(i->'old',i->'new')::text,'UTF8')),
  sha256(convert_to(nullif(i->'old','null'::jsonb)::text,'UTF8')),sha256(convert_to(nullif(i->'new','null'::jsonb)::text,'UTF8')),
  nullif(i->'old','null'::jsonb),nullif(i->'new','null'::jsonb),(i->>'command')::integer,
  frozen#>'{mirror,origins}'->((i->>'command')::integer-1),(i->>'required')::boolean,(i->>'outbox')::integer
 FROM jsonb_array_elements(images) WITH ORDINALITY q(i,n);
 UPDATE pg_temp.kaname_binding_mirror_images i SET epoch_keys=(
  SELECT to_jsonb(array_remove(ARRAY[
   CASE WHEN subject ~ '^(user|service_account):[^#*]+$' THEN subject
 WHEN subject ~ '^(group|iam_group):[^#*]+#member$' THEN 'group:'||split_part(split_part(subject,':',2),'#',1)
 WHEN subject ~ '^(account|project|cluster):[^#*]+$' THEN NULL ELSE '*' END],NULL))||(frozen#>'{mirror,policy_objects}'->((coalesce(i.new_image,i.old_image)->>'object_type')||':'||(coalesce(i.new_image,i.old_image)->>'object_id'))) FROM (SELECT coalesce(i.new_image,i.old_image)->>'subject' AS subject) q)
 WHERE i.table_name='relation_fact';
 IF EXISTS(SELECT 1 FROM pg_temp.kaname_binding_mirror_images i CROSS JOIN pg_temp.kaname_binding_mirror_program p
  WHERE i.table_name='relation_fact' AND (i.epoch_keys IS NULL OR NOT p.policy_keys @> i.epoch_keys)) THEN
  RAISE EXCEPTION 'binding mirror policy final keys exceed held maximum' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_binding_mirror_program SET final_clock=at_time,frozen='{}'::jsonb WHERE singleton;
END $$;

CREATE FUNCTION kaname._authority_binding_mirror_before_write_v3(p_table text,p_operation text,p_old jsonb,p_new jsonb) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE metadata jsonb;proof jsonb;header jsonb;v_row_value jsonb;identifier bigint;candidate jsonb;v_image_hash bytea;matched record;sequence_origin jsonb;
BEGIN
 IF p_table NOT IN ('access_binding_target_members','access_binding_emitted_tuples','fga_outbox','relation_fact') THEN RETURN false;END IF;
 metadata:=kaname._authority_binding_mirror_store_v3();IF metadata IS NULL THEN RETURN false;END IF;
 proof:=kaname.authority_protocol_attestation();
 IF metadata->>'final_clock' IS NULL OR metadata->>'final_clock' IS DISTINCT FROM proof->>'decision_at'
 OR metadata->>'epoch_clock' IS DISTINCT FROM proof->>'decision_at' THEN
  RAISE EXCEPTION 'binding mirror write before final held proof' USING ERRCODE='42501';END IF;
 header:=kaname._authority_sequence_header_v3();
 IF header IS NULL OR header->>'family' IS DISTINCT FROM 'binding' OR header->'selected'='null'::jsonb THEN
  RAISE EXCEPTION 'binding mirror selected sequence absent' USING ERRCODE='42501';END IF;
 IF p_table IN ('access_binding_target_members','access_binding_emitted_tuples') THEN
  IF (p_old IS NOT NULL AND p_old->>'binding_id' IS DISTINCT FROM metadata->>'binding')
  OR (p_new IS NOT NULL AND p_new->>'binding_id' IS DISTINCT FROM metadata->>'binding') THEN
   RAISE EXCEPTION 'binding mirror physical binding differs from prepared witness' USING ERRCODE='42501';END IF;
 ELSIF p_table='fga_outbox' THEN
  IF p_operation<>'INSERT' OR p_old IS NOT NULL THEN RETURN false;END IF;
  identifier:=(p_new->>'id')::bigint;v_row_value:=p_new-'id';
  IF NOT EXISTS(SELECT 1 FROM pg_temp.kaname_authority_sequence_effects e WHERE e.nonce=(header->>'nonce')::uuid
   AND e.table_name='fga_outbox' AND e.reserved_id=identifier AND e.selected AND e.claimed AND NOT e.consumed
   AND e.origin->>'family'='binding.stage' AND e.origin->>'binding'=metadata->>'binding' AND e.row_value=v_row_value) THEN
   RAISE EXCEPTION 'binding mirror journal differs from selected sequence row' USING ERRCODE='42501';END IF;
  SELECT e.origin INTO STRICT sequence_origin FROM pg_temp.kaname_authority_sequence_effects e
   WHERE e.nonce=(header->>'nonce')::uuid AND e.table_name='fga_outbox' AND e.reserved_id=identifier;
  p_new:=v_row_value;
 END IF;
 v_image_hash:=sha256(convert_to(jsonb_build_array(p_old,p_new)::text,'UTF8'));
 SELECT i.* INTO matched FROM pg_temp.kaname_binding_mirror_images i
 WHERE i.table_name=p_table AND i.operation=p_operation AND i.image_hash=v_image_hash
 AND i.old_image IS NOT DISTINCT FROM p_old AND i.new_image IS NOT DISTINCT FROM p_new
 AND NOT i.attempted
 AND i.command_no=(SELECT p.active_command FROM pg_temp.kaname_binding_mirror_program p WHERE singleton)
 AND (p_table<>'relation_fact' OR i.outbox_no=(SELECT p.active_outbox FROM pg_temp.kaname_binding_mirror_program p WHERE singleton))
 AND (sequence_origin IS NULL OR (i.origin->'command'=sequence_origin->'command' AND i.origin->'coordinate'=sequence_origin->'coordinate'))
 ORDER BY i.command_no,i.image_no LIMIT 1;
 IF NOT FOUND THEN RAISE EXCEPTION 'binding mirror physical image absent or replayed' USING ERRCODE='42501';END IF;
 IF EXISTS(SELECT 1 FROM pg_temp.kaname_binding_mirror_images i
  WHERE i.command_no<matched.command_no AND ((i.required AND NOT i.consumed) OR (i.table_name='fga_outbox' AND NOT i.folded))) THEN
  RAISE EXCEPTION 'binding mirror command precedes required effects' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_binding_mirror_images SET attempted=true WHERE image_no=matched.image_no;
 RETURN true;
END $$;

-- RR compiler замыкает один полный binding. Owner хранит проверенный
-- maximum; caller получает только счётчики, не разрешение и не reserved IDs.
CREATE FUNCTION kaname.authority_binding_stage_sequence_capture_v3(p_input jsonb,p_accounts text[],p_epochs jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE invoker oid;owner_oid oid;source_index jsonb;entry record;actual record;bundle record;
 binding jsonb;selectors jsonb;members jsonb;ledger jsonb;subjects integer;types text[]:=ARRAY[]::text[];
 catalog jsonb;coordinate jsonb;typ text;identifier text;graph jsonb;ancestry jsonb;certificate jsonb;
 current_members jsonb;current_ledger jsonb;member_proof jsonb;ledger_proof jsonb;
 member_partitions jsonb;ledger_partitions jsonb;
 supplied jsonb:='{}'::jsonb;commands jsonb:='[]'::jsonb;maximum jsonb:='[]'::jsonb;
 command jsonb;tuple_value jsonb;seen_tuples jsonb;key text;supplied_count integer;
 narrow boolean;global_scope boolean;mirror_local boolean;accounts text[];scope_result record;grantee record;
 used_rows integer:=0;used_reads integer:=0;mirror_keys jsonb:='{}';mirror jsonb;coordinate_no integer:=0;policy_objects jsonb:='{}';policy_scopes jsonb;policy_model text;policy_state jsonb;policy_account text;
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
 -- Полные owner-проверенные строки делятся один раз, без DISTINCT и фильтра статусов.
 -- Порядок внутри coordinate сохраняет исходную последовательность witnesses.
 -- НАЧАЛО разбиения coordinate
 WITH member_groups AS (
  SELECT jsonb_build_array(s.value->2->>'object_type',s.value->2->>'object_id')::text COLLATE "C" AS coordinate_key,
   jsonb_agg(s.value->2 ORDER BY s.position) AS rows_value
  FROM jsonb_array_elements(members->'states') WITH ORDINALITY s(value,position)
  GROUP BY jsonb_build_array(s.value->2->>'object_type',s.value->2->>'object_id')::text COLLATE "C"
 ), ledger_groups AS (
  SELECT jsonb_build_array(s.value->2->>'member_object_type',s.value->2->>'member_object_id')::text COLLATE "C" AS coordinate_key,
   jsonb_agg(s.value->2 ORDER BY s.position) AS rows_value
  FROM jsonb_array_elements(ledger->'states') WITH ORDINALITY s(value,position)
  GROUP BY jsonb_build_array(s.value->2->>'member_object_type',s.value->2->>'member_object_id')::text COLLATE "C"
 )
 SELECT coalesce((SELECT jsonb_object_agg(coordinate_key,rows_value) FROM member_groups),'{}'::jsonb),
  coalesce((SELECT jsonb_object_agg(coordinate_key,rows_value) FROM ledger_groups),'{}'::jsonb)
 INTO member_partitions,ledger_partitions;
 -- КОНЕЦ разбиения coordinate
 -- Тот же coordinate order, что keyset typ/id; map iteration caller его не выбирает.
 FOR coordinate IN SELECT value FROM jsonb_array_elements(p_input->'coordinates') ORDER BY value->>'type' COLLATE "C",value->>'id' COLLATE "C" LOOP
  coordinate_no:=coordinate_no+1;typ:=coordinate->>'type';identifier:=coordinate->>'id';
  graph:=kaname._authority_resource_projection_v2(source_index,typ,identifier);
  ancestry:=kaname._authority_resource_ancestor_graph_v2(source_index,catalog,graph);
  graph:=graph||jsonb_build_object('ancestors',ancestry->'ancestors');
  certificate:=kaname._authority_resource_coordinate_certificate_v2(source_index,catalog,binding->>'id',graph,coordinate->'desired');
  key:=jsonb_build_array(typ,identifier)::text;
  current_members:=coalesce(member_partitions->key,'[]'::jsonb);
  current_ledger:=coalesce(ledger_partitions->key,'[]'::jsonb);
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
  mirror_local:=false;
  IF NOT global_scope AND typ NOT IN ('iam.account','iam.project','iam.role','iam.group','iam.serviceAccount','iam.accessBinding','iam.user') THEN
   mirror_local:=kaname._authority_binding_mirror_locality_v3(source_index,catalog,graph,binding,coordinate,current_ledger);
   global_scope:=NOT mirror_local;
   IF mirror_local THEN mirror_keys:=mirror_keys||jsonb_build_object(coordinate_no::text,jsonb_build_array(typ,identifier));END IF;
  END IF;
  IF mirror_local OR typ='iam.group' THEN
   policy_model:=CASE WHEN typ='iam.group' THEN 'iam_group' ELSE NULL END;
   IF policy_model IS NULL THEN
    SELECT r->>'ObjectType' INTO STRICT policy_model FROM jsonb_array_elements(catalog#>'{Live,Resources}') r
     WHERE (r->>'Module')||'.'||(r->>'Resource')=typ;
   END IF;
   SELECT coalesce(jsonb_agg('scope:'||a ORDER BY a COLLATE "C"),'[]'::jsonb) INTO policy_scopes FROM jsonb_object_keys(graph->'accounts') a;
   IF mirror_local THEN
    FOR policy_state IN SELECT value FROM jsonb_array_elements(kaname._authority_resource_require_capture_v2(source_index,4,policy_model,identifier)->'states') LOOP
     policy_account:=policy_state->2->>'account_id';
     IF coalesce(policy_account,'')='' THEN RAISE EXCEPTION 'binding retained policy owner absent' USING ERRCODE='42501';END IF;
     policy_scopes:=policy_scopes||jsonb_build_array('scope:'||policy_account);
    END LOOP;
   END IF;
   -- Legacy object lookup при отсутствии current owner инвалидировал ROOT.
   -- Retained области добавляются, но не отменяют этот исходный ROOT эффект.
   IF graph->'current_accounts'='[]'::jsonb THEN policy_scopes:=policy_scopes||jsonb_build_array('*');END IF;
   SELECT coalesce(jsonb_agg(DISTINCT k ORDER BY k),'[]'::jsonb) INTO policy_scopes FROM jsonb_array_elements(policy_scopes) k;
   policy_objects:=policy_objects||jsonb_build_object(policy_model||':'||identifier,policy_scopes);
  END IF;
  seen_tuples:='{}'::jsonb;
  FOR command IN SELECT value FROM jsonb_array_elements(coordinate->'commands') LOOP
   IF command->>'Kind' NOT IN ('write','delete') THEN CONTINUE;END IF;
   FOR tuple_value IN SELECT value FROM jsonb_array_elements(command->'Tuples') LOOP
    key:=jsonb_build_array(command->>'Kind',tuple_value)::text;
    IF seen_tuples ? key THEN RAISE EXCEPTION 'binding duplicate physical tuple within coordinate' USING ERRCODE='42501';END IF;
    seen_tuples:=seen_tuples||jsonb_build_object(key,true);
    IF NOT mirror_local AND tuple_value->>'Object' NOT LIKE 'iam_group:%' THEN global_scope:=true;END IF;
   END LOOP;
  END LOOP;
 END LOOP;
 SELECT coalesce(array_agg(DISTINCT x COLLATE "C" ORDER BY x COLLATE "C"),ARRAY[]::text[]) INTO accounts FROM unnest(accounts) x;
 IF cardinality(accounts)>256 OR (mirror_keys<>'{}'::jsonb AND (cardinality(accounts)<>1 OR accounts[1] IS DISTINCT FROM binding->>'resource_id')) THEN global_scope:=true;END IF;
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
 -- Подлинные canonical OLD строки и commands остаются private owner witness.
 -- Порядок физического применения: все обычные commands, затем delete phase.
 IF NOT global_scope AND mirror_keys<>'{}'::jsonb THEN
  SELECT jsonb_build_object('binding',binding,'coordinates',mirror_keys,'origins',jsonb_agg(c-'body' ORDER BY CASE WHEN c#>>'{body,Kind}'='delete' THEN 1 ELSE 0 END,(c->>'command')::integer),'commands',coalesce(jsonb_agg(c->'body'
   ORDER BY CASE WHEN c#>>'{body,Kind}'='delete' THEN 1 ELSE 0 END,(c->>'command')::integer),'[]'::jsonb))
  INTO mirror FROM jsonb_array_elements(commands) c;
  mirror:=mirror||jsonb_build_object('policy_objects',policy_objects,'budget_reads',p_reads-used_reads,'budget_rows',p_rows-used_rows,'members',(SELECT coalesce(jsonb_agg(s->2),'[]'::jsonb) FROM jsonb_array_elements(members->'states') s
   WHERE true),
   'ledger',(SELECT coalesce(jsonb_agg(s->2),'[]'::jsonb) FROM jsonb_array_elements(ledger->'states') s
   WHERE true));
 END IF;
 CREATE TEMP TABLE kaname_binding_sequence_snapshot(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),backend integer NOT NULL,
  invoker_oid oid NOT NULL,stage_xid text NOT NULL,binding_id text NOT NULL,model_id text NOT NULL,catalog_id text NOT NULL,projector_version text NOT NULL,
  accounts text[],epochs jsonb NOT NULL,expires_at timestamptz,commands jsonb NOT NULL,maximum jsonb NOT NULL,mirror jsonb,locked_xid text,locked_at timestamptz,consumed boolean NOT NULL DEFAULT false) ON COMMIT PRESERVE ROWS;
 REVOKE ALL ON pg_temp.kaname_binding_sequence_snapshot FROM PUBLIC;
 FOR grantee IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE c.oid='pg_temp.kaname_binding_sequence_snapshot'::regclass AND a.grantee<>owner_oid LOOP
  EXECUTE format('REVOKE ALL ON pg_temp.kaname_binding_sequence_snapshot FROM %I',grantee.rolname);
 END LOOP;
 INSERT INTO pg_temp.kaname_binding_sequence_snapshot(backend,invoker_oid,stage_xid,binding_id,model_id,catalog_id,projector_version,accounts,epochs,expires_at,commands,maximum,mirror)
 VALUES(pg_backend_pid(),invoker,pg_current_xact_id()::text,binding->>'id',bundle.model_id,bundle.catalog_id,bundle.projector_version,accounts,p_epochs,(binding->>'expires_at')::timestamptz,commands,maximum,mirror);
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
DECLARE snapshot jsonb;proof jsonb;expected jsonb;actual jsonb;used integer;count_rows integer;mirror_cost record;
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
 SELECT * INTO STRICT mirror_cost FROM kaname._authority_binding_mirror_prepare_v3(snapshot,p_rows-count_rows,p_reads-2);
 count_rows:=count_rows+mirror_cost.logical_rows;
 used:=kaname._authority_sequence_reserve_v3('binding',snapshot->'maximum',p_reads-2-mirror_cost.logical_reads);
 PERFORM kaname._authority_sequence_freeze_v3(jsonb_build_object('kind','binding.stage','binding',p_binding,
  'expires_at',snapshot->'expires_at','epochs',p_epochs,'accounts',snapshot->'accounts'));
 UPDATE pg_temp.kaname_binding_sequence_snapshot SET consumed=true WHERE singleton;
 RETURN QUERY SELECT count_rows,used+2+mirror_cost.logical_reads;
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
 PERFORM kaname._authority_binding_mirror_finalize_v3(p_binding);
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
 WHEN 4 THEN table_name:='resource_registration_scope';predicate:='r.object_type=$1 AND r.object_id=$2';
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
 IF proof IS NULL THEN
  IF TG_TABLE_NAME='fga_outbox' THEN
   PERFORM kaname._authority_forward_row_v4((to_jsonb(NEW)->>'id')::bigint,to_jsonb(NEW)-'id',true);
  END IF;
  RETURN NULL;
 END IF;
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
 IF proof IS NULL OR p_family NOT IN ('binding','role','group_add') OR p_family IS NULL THEN RAISE EXCEPTION 'invalid sequence expectation' USING ERRCODE='42501';END IF;
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
  IF program->>'family'='group_add' THEN
   IF TG_TABLE_NAME<>'group_members' OR TG_OP<>'INSERT' OR TG_WHEN<>'AFTER' OR matches<>1
   OR (kaname._authority_group_add_program_v3())#>>'{command_state,member_attempted}'<>'true'
   OR (kaname._authority_group_add_program_v3())#>>'{command_state,member_inserted}'<>'false' THEN
    RAISE EXCEPTION 'group addition actual member origin differs' USING ERRCODE='42501';END IF;
   UPDATE pg_temp.kaname_group_add_command SET member_inserted=true WHERE singleton;
  END IF;
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
 OR p_family IS NULL OR p_family NOT IN ('resource','binding','role','cluster','metadata','sa_state','group_add')
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
 PERFORM kaname._authority_group_add_complete_v3();
 IF kaname._authority_binding_mirror_store_v3() IS NOT NULL THEN
  IF EXISTS(SELECT 1 FROM pg_temp.kaname_binding_mirror_program WHERE final_clock IS NULL OR active_command IS NOT NULL OR next_command<>jsonb_array_length(commands)+1 OR audit_rows<>'{}'::jsonb)
  OR EXISTS(SELECT 1 FROM pg_temp.kaname_binding_mirror_images WHERE (required AND NOT consumed)
   OR (table_name='fga_outbox' AND NOT folded)) THEN
   RAISE EXCEPTION 'binding mirror required program incomplete' USING ERRCODE='42501';END IF;
 END IF;
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
  OR (row_value->'payload')-ARRAY['user','object','relation','relations']<>'{}'::jsonb THEN
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
  IF expected IS NULL OR expected->'row' IS DISTINCT FROM (outbox->'row')-'created_at'
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
-- Только FULL Add: frozen команда не меняет typed Remove/lifecycle.
-- Программа effects хранит exact origin/row и ID; отдельный приватный ряд
-- доказывает выполнение тела, в том числе INSERT ON CONFLICT DO NOTHING.
CREATE FUNCTION kaname._authority_group_add_program_v3() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb; state_oid oid; sequence_oid oid; owner_oid oid; state jsonb;
BEGIN
 state_oid:=to_regclass('pg_temp.kaname_group_add_command');
 IF state_oid IS NOT NULL THEN
  SELECT oid INTO STRICT owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=state_oid AND relowner=owner_oid AND relkind='r' AND relpersistence='t')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
  WHERE c.oid=state_oid AND a.grantee<>owner_oid)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) x
  WHERE a.attrelid=state_oid AND x.grantee<>owner_oid) THEN
  RAISE EXCEPTION 'untrusted group addition command storage' USING ERRCODE='42501';END IF;
 SELECT to_jsonb(s) INTO state FROM pg_temp.kaname_group_add_command s WHERE singleton;
 END IF;
 IF state IS NULL THEN
  -- Отсутствующий/пустой private state не превращает уже зарезервированный
  -- Add в обычный default. При другой family сохраняется прежний путь без
  -- требования attestation для обычных subject-change producers.
  sequence_oid:=to_regclass('pg_temp.kaname_authority_sequence_program');
  IF sequence_oid IS NOT NULL THEN
   -- Владелец нужен только для существующего storage. При двух отсутствующих
   -- таблицах нет ни строки private-программы, ни объекта для проверки ACL.
   IF owner_oid IS NULL THEN
    SELECT oid INTO STRICT owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
   END IF;
   IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=sequence_oid AND relowner=owner_oid AND relkind='r' AND relpersistence='t')
   OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
    WHERE c.oid=sequence_oid AND a.grantee<>owner_oid) THEN
    RAISE EXCEPTION 'untrusted group addition sequence storage' USING ERRCODE='42501';END IF;
   IF EXISTS(SELECT 1 FROM pg_temp.kaname_authority_sequence_program WHERE family='group_add') THEN
    RAISE EXCEPTION 'group addition command storage disappeared' USING ERRCODE='42501';END IF;
  END IF;
  RETURN NULL;
 END IF;
 program:=kaname._authority_sequence_store_v3();
 IF program IS NULL OR program->>'family' IS DISTINCT FROM 'group_add'
 OR state_oid IS DISTINCT FROM (program#>>'{frozen,state_oid}')::oid
 OR state->>'nonce' IS DISTINCT FROM program->>'nonce'
 OR program#>>'{frozen,kind}' IS DISTINCT FROM 'group.add'
 OR (SELECT count(*) FROM pg_temp.kaname_group_add_command)<>1 THEN
  RAISE EXCEPTION 'group addition command lifetime changed' USING ERRCODE='42501';END IF;
 RETURN program||jsonb_build_object('command_state',state);
END $$;

CREATE FUNCTION kaname.authority_group_add_prepare_v3(p_request jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; group_row jsonb; locked_group jsonb; old_member jsonb; old_fact jsonb;
 member_template jsonb; fact_insert jsonb; fact_final jsonb; subject_row jsonb;
 d3 jsonb; target jsonb; valid boolean; duplicate boolean; invoker oid; owner_oid oid;
 table_name text; keys text[]; k text; maximum jsonb:='[]'; source_rows integer:=0; source_reads integer:=0;
 cost integer; reserved_subject_id bigint; state_oid oid; grant_row record; member_keys text[]; fact_keys text[];
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'group' OR proof->>'purpose' IS DISTINCT FROM 'decision'
 OR proof->>'writer_contract' IS DISTINCT FROM '2' OR proof->>'consumer_profile' IS DISTINCT FROM 'full'
 OR proof->>'consumer_finalized' IS DISTINCT FROM 'true'
 OR jsonb_typeof(p_request) IS DISTINCT FROM 'object'
 OR p_request-ARRAY['group_id','member_type','member_id']<>'{}'::jsonb
 OR jsonb_typeof(p_request->'group_id') IS DISTINCT FROM 'string'
 OR jsonb_typeof(p_request->'member_id') IS DISTINCT FROM 'string'
 OR p_request->>'group_id' !~ '^[^:#*[:space:]]+$' OR p_request->>'member_id' !~ '^[^:#*[:space:]]+$'
 OR coalesce(p_request->>'member_type','') NOT IN ('user','service_account') THEN
  RAISE EXCEPTION 'group addition requires closed FULL decision request' USING ERRCODE='42501';END IF;
 IF p_rows IS NULL OR p_rows NOT BETWEEN 1 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 1 AND 4096 THEN
  RAISE EXCEPTION 'group addition preparation budget absent' USING ERRCODE='54000';END IF;
 IF kaname._authority_sequence_store_v3() IS NOT NULL THEN
  RAISE EXCEPTION 'group addition command already prepared' USING ERRCODE='42501';END IF;
 PERFORM kaname._authority_sequence_expect_v3('group_add');
 invoker:=(proof->>'invoker_oid')::oid;
 -- Оригинальные права тела проверяются до SD чтений/резерва; EXECUTE не
 -- предоставляет ни нового INSERT/UPDATE, ни доступа к sequence без USAGE.
 FOREACH table_name IN ARRAY ARRAY['groups','accounts','group_members','relation_fact',
  CASE WHEN p_request->>'member_type'='user' THEN 'users' ELSE 'service_accounts' END] LOOP
  IF NOT has_table_privilege(invoker,to_regclass('kaname.'||table_name),'SELECT') THEN
   RAISE EXCEPTION 'group addition original SELECT privilege absent' USING ERRCODE='42501';END IF;
 END LOOP;
 IF NOT has_table_privilege(invoker,'kaname.group_members','INSERT')
 OR NOT has_table_privilege(invoker,'kaname.relation_fact','INSERT') OR NOT has_table_privilege(invoker,'kaname.relation_fact','UPDATE')
 OR NOT has_table_privilege(invoker,'kaname.subject_change_outbox','INSERT')
 OR NOT has_sequence_privilege(invoker,'kaname.subject_change_outbox_id_seq','USAGE,UPDATE')
 OR (p_request->>'member_type'='user' AND (NOT has_table_privilege(invoker,'kaname.memberships','SELECT')
  OR NOT has_any_column_privilege(invoker,'kaname.memberships','UPDATE')))
 OR NOT has_any_column_privilege(invoker,to_regclass('kaname.'||CASE WHEN p_request->>'member_type'='user' THEN 'users' ELSE 'service_accounts' END),'UPDATE') THEN
  RAISE EXCEPTION 'group addition original body privileges absent' USING ERRCODE='42501';END IF;
 -- RX actual union предшествует каждому row/unique/sequence ожиданию.
 LOCK TABLE kaname.authority_policy_epoch,kaname.fga_outbox,kaname.group_members,
  kaname.relation_fact,kaname.resource_journal,kaname.subject_change_outbox IN ROW EXCLUSIVE MODE;
 LOCK TABLE kaname.accounts,kaname.groups IN ROW SHARE MODE;
 IF p_request->>'member_type'='user' THEN LOCK TABLE kaname.memberships,kaname.users IN ROW SHARE MODE;
 ELSE LOCK TABLE kaname.service_accounts IN ROW SHARE MODE;END IF;
 source_reads:=source_reads+8;
 SELECT to_jsonb(g) INTO group_row FROM ONLY kaname.groups g WHERE id=p_request->>'group_id';
 source_reads:=source_reads+1;source_rows:=source_rows+1;
 IF group_row IS NULL OR (proof->>'mode'<>'global' AND NOT (proof->'accounts' ? (group_row->>'account_id'))) THEN
  RAISE EXCEPTION 'group addition owner scope changed' USING ERRCODE='P1034';END IF;
 member_template:=p_request||jsonb_build_object('added_at',NULL);
 member_keys:=ARRAY['group:'||(p_request->>'group_id'),(p_request->>'member_type')||':'||(p_request->>'member_id')];
 fact_keys:=ARRAY[(p_request->>'member_type')||':'||(p_request->>'member_id'),'scope:'||(group_row->>'account_id')];
 SELECT array_agg(DISTINCT value COLLATE "C" ORDER BY value COLLATE "C") INTO keys FROM unnest(member_keys||fact_keys) value;
 -- Coordinator уже исключает чужой signed writer той же account и GLOBAL.
 -- Policy root -> exact keys -> physical tuples: все новые ожидания до второго
 -- protectPolicyPlan. Отсутствующая ссылка не создаёт epoch и не раскрывает D3.
 PERFORM key FROM kaname.authority_policy_epoch WHERE key='*' FOR SHARE;
 source_reads:=source_reads+1;source_rows:=source_rows+1;
 FOREACH k IN ARRAY keys LOOP
  PERFORM key FROM kaname.authority_policy_epoch WHERE key=k FOR UPDATE;
  source_reads:=source_reads+1;source_rows:=source_rows+CASE WHEN FOUND THEN 1 ELSE 0 END;
  IF NOT FOUND AND k<>((p_request->>'member_type')||':'||(p_request->>'member_id')) THEN
   RAISE EXCEPTION 'group addition policy epoch disappeared' USING ERRCODE='P1034';END IF;
 END LOOP;
 SELECT to_jsonb(g) INTO locked_group FROM ONLY kaname.groups g WHERE id=p_request->>'group_id' FOR SHARE;
 source_reads:=source_reads+1;source_rows:=source_rows+1;
 IF locked_group IS DISTINCT FROM group_row THEN RAISE EXCEPTION 'group addition parent changed' USING ERRCODE='P1034';END IF;
 PERFORM id FROM ONLY kaname.accounts WHERE id=group_row->>'account_id' FOR KEY SHARE;
 source_reads:=source_reads+1;source_rows:=source_rows+1;
 IF NOT FOUND THEN RAISE EXCEPTION 'group addition account disappeared' USING ERRCODE='P1034';END IF;
 -- Исходный D3 фильтрует own ACTIVE membership/SA account ДО row lock.
 -- Чужая и отсутствующая ссылка не ждут чужого пользователя/SA; FK target
 -- нужен только после подтверждённого own membership и тоже до final clock.
 IF p_request->>'member_type'='user' THEN
  SELECT to_jsonb(m) INTO d3 FROM ONLY kaname.memberships m
   WHERE user_id=p_request->>'member_id' AND account_id=group_row->>'account_id' AND state='ACTIVE' FOR SHARE;
  source_reads:=source_reads+1;
  IF d3 IS NOT NULL THEN
   SELECT to_jsonb(u) INTO target FROM ONLY kaname.users u WHERE id=p_request->>'member_id' FOR KEY SHARE;
   source_reads:=source_reads+1;
  END IF;
  valid:=d3 IS NOT NULL AND target IS NOT NULL;
 ELSE
  SELECT to_jsonb(s) INTO target FROM ONLY kaname.service_accounts s
   WHERE id=p_request->>'member_id' AND account_id=group_row->>'account_id' FOR SHARE;
  valid:=target IS NOT NULL;source_reads:=source_reads+1;
 END IF;
 valid:=coalesce(valid,false);
 source_rows:=source_rows+CASE WHEN target IS NULL THEN 0 ELSE 1 END+CASE WHEN d3 IS NULL THEN 0 ELSE 1 END;
 -- Отсутствие PK защищено уже удостоверенным EXCLUSIVE account coordinator
 -- (либо обоими GLOBAL barriers). Runtime не может писать эту группу/факт в
 -- чужом account scope: существующий OLD/NEW backstop остаётся включённым.
 SELECT to_jsonb(m) INTO old_member FROM ONLY kaname.group_members m
  WHERE group_id=p_request->>'group_id' AND member_type=p_request->>'member_type' AND member_id=p_request->>'member_id' FOR UPDATE;
 SELECT to_jsonb(f) INTO old_fact FROM ONLY kaname.relation_fact f
  WHERE object_type='group' AND object_id=p_request->>'group_id' AND relation='member'
   AND subject=(p_request->>'member_type')||':'||(p_request->>'member_id') FOR UPDATE;
 source_reads:=source_reads+2;source_rows:=source_rows+CASE WHEN old_member IS NULL THEN 0 ELSE 1 END+CASE WHEN old_fact IS NULL THEN 0 ELSE 1 END;
 duplicate:=old_member IS NOT NULL;
 fact_insert:=to_jsonb(jsonb_populate_record(NULL::kaname.relation_fact,jsonb_build_object(
  'object_type','group','object_id',p_request->>'group_id','relation','member',
  'subject',(p_request->>'member_type')||':'||(p_request->>'member_id'),'source_version',transaction_timestamp(),
  'created_at',transaction_timestamp(),'condition_name','','condition_params','{}'::jsonb)));
 fact_final:=CASE WHEN old_fact IS NULL THEN fact_insert
  WHEN (old_fact->>'source_version')::timestamptz<transaction_timestamp()
   THEN old_fact||jsonb_build_object('source_version',transaction_timestamp(),'condition_name','') ELSE old_fact END;
 IF valid THEN
  IF NOT duplicate THEN maximum:=jsonb_build_array(jsonb_build_object('ordinal',1,'table','resource_journal','origin','{}'::jsonb,'row','{}'::jsonb,'stamp','transaction'));END IF;
  maximum:=maximum||jsonb_build_array(jsonb_build_object('ordinal',jsonb_array_length(maximum)+1,'table','fga_outbox','origin','{}'::jsonb,'row','{}'::jsonb,'stamp','transaction'));
  -- Имя резерва отделено от колонки subject_id той же очереди.
  reserved_subject_id:=nextval('kaname.subject_change_outbox_id_seq');
  IF reserved_subject_id<=0 THEN RAISE EXCEPTION 'group addition subject identity exhausted' USING ERRCODE='P1034';END IF;
  PERFORM pg_advisory_xact_lock(1262569301,hashtext(reserved_subject_id::text));
  PERFORM o.id FROM ONLY kaname.subject_change_outbox o WHERE o.id=reserved_subject_id FOR UPDATE;
  IF FOUND THEN RAISE EXCEPTION 'group addition subject identity collided' USING ERRCODE='P1034';END IF;
  source_reads:=source_reads+2;
  subject_row:=to_jsonb(jsonb_populate_record(NULL::kaname.subject_change_outbox,jsonb_build_object(
   'id',reserved_subject_id,'subject_id',p_request->>'member_id','op','group_member_change','event_type','group_member_change',
   'created_at',transaction_timestamp(),'payload',jsonb_build_object('subject_id',p_request->>'member_id',
    'subject_type',p_request->>'member_type','op','group_member_change','event_type','group_member_change'))));
 END IF;
 source_rows:=source_rows+jsonb_array_length(maximum)+CASE WHEN valid THEN 1 ELSE 0 END;
 IF source_rows>p_rows OR source_reads>p_reads THEN RAISE EXCEPTION 'group addition source budget exceeded' USING ERRCODE='54000';END IF;
 cost:=kaname._authority_sequence_reserve_v3('group_add',maximum,p_reads-source_reads);
 SELECT oid INTO STRICT owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
 state_oid:=to_regclass('pg_temp.kaname_group_add_command');
 IF state_oid IS NULL THEN
  CREATE TEMP TABLE pg_temp.kaname_group_add_command(singleton boolean PRIMARY KEY CHECK(singleton),nonce uuid NOT NULL,
   member_attempted boolean NOT NULL DEFAULT false,member_inserted boolean NOT NULL DEFAULT false,
   fold_active boolean NOT NULL DEFAULT false,fold_done boolean NOT NULL DEFAULT false,
   fact_attempted boolean NOT NULL DEFAULT false,fact_updated boolean NOT NULL DEFAULT false,
   subject_claimed boolean NOT NULL DEFAULT false,subject_done boolean NOT NULL DEFAULT false) ON COMMIT DELETE ROWS;
  REVOKE ALL ON pg_temp.kaname_group_add_command FROM PUBLIC;
  FOR grant_row IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
   JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE c.oid='pg_temp.kaname_group_add_command'::regclass AND a.grantee<>owner_oid LOOP
   EXECUTE format('REVOKE ALL ON pg_temp.kaname_group_add_command FROM %I',grant_row.rolname);
  END LOOP;
  state_oid:='pg_temp.kaname_group_add_command'::regclass;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=state_oid AND relowner=owner_oid AND relpersistence='t' AND relkind='r')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE c.oid=state_oid AND a.grantee<>owner_oid)
 OR (SELECT array_agg(attname::text ORDER BY attnum) FROM pg_catalog.pg_attribute WHERE attrelid=state_oid AND attnum>0 AND NOT attisdropped)
  IS DISTINCT FROM ARRAY['singleton','nonce','member_attempted','member_inserted','fold_active','fold_done','fact_attempted','fact_updated','subject_claimed','subject_done']
 OR (SELECT array_agg(atttypid ORDER BY attnum) FROM pg_catalog.pg_attribute WHERE attrelid=state_oid AND attnum>0 AND NOT attisdropped)
  IS DISTINCT FROM ARRAY['boolean'::regtype::oid,'uuid'::regtype::oid,'boolean'::regtype::oid,'boolean'::regtype::oid,'boolean'::regtype::oid,'boolean'::regtype::oid,'boolean'::regtype::oid,'boolean'::regtype::oid,'boolean'::regtype::oid,'boolean'::regtype::oid] THEN
  RAISE EXCEPTION 'untrusted group addition command shape' USING ERRCODE='42501';END IF;
 INSERT INTO pg_temp.kaname_group_add_command(singleton,nonce) VALUES(true,(proof->>'nonce')::uuid);
 PERFORM kaname._authority_sequence_freeze_v3(jsonb_build_object('kind','group.add','mode','mutation',
  'request',p_request,'state_oid',state_oid,'reference_valid',valid,'duplicate',duplicate,'group',group_row,
  'old_member',old_member,'member_template',member_template,'old_fact',old_fact,'fact_insert',fact_insert,'fact_final',fact_final,
  'subject',subject_row,'member_keys',to_jsonb(member_keys),'fact_keys',to_jsonb(fact_keys)));
 RETURN jsonb_build_object('rows',source_rows,'reads',source_reads+cost);
END $$;

CREATE FUNCTION kaname.authority_group_add_finalize_v3(p_request jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(reference_valid boolean,added_at timestamptz,logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb; proof jsonb; frozen jsonb; selected jsonb:='[]'; member_row jsonb; n integer:=0;
BEGIN
 program:=kaname._authority_group_add_program_v3();proof:=kaname.authority_protocol_attestation();frozen:=program->'frozen';
 IF program IS NULL OR proof IS NULL OR frozen->'request' IS DISTINCT FROM p_request
 OR program->'selected'<>'null'::jsonb OR proof->>'consumer_finalized' IS DISTINCT FROM 'true'
 OR (proof->>'decision_at')::timestamptz<=(program->>'staged_decision_at')::timestamptz THEN
  RAISE EXCEPTION 'group addition final decision/request changed' USING ERRCODE='42501';END IF;
 IF p_rows IS NULL OR p_rows<0 OR p_reads IS NULL OR p_reads<1 THEN
  RAISE EXCEPTION 'group addition finalization budget absent' USING ERRCODE='54000';END IF;
 added_at:=(proof->>'decision_at')::timestamptz;reference_valid:=(frozen->>'reference_valid')::boolean;
 IF reference_valid THEN
  IF NOT (frozen->>'duplicate')::boolean THEN
   n:=n+1;member_row:=(frozen->'member_template')||jsonb_build_object('added_at',added_at);
   selected:=jsonb_build_array(jsonb_build_object('ordinal',n,'origin',jsonb_build_object(
    'table','group_members','operation','INSERT','when','AFTER','old',NULL,'new',member_row),
    'row',jsonb_build_object('resource_kind','iam_group','resource_id',p_request->>'group_id',
     'project_id',kaname.resource_journal_project('iam_group',frozen->'group'),
     'scope',kaname.resource_journal_scope('iam_group',frozen->'group'),'event_type','UPDATED',
     'payload',jsonb_build_object('id',p_request->>'group_id'))));
  END IF;
  n:=n+1;selected:=selected||jsonb_build_array(jsonb_build_object('ordinal',n,
   'origin',jsonb_build_object('family','group.add','request',p_request),
   'row',jsonb_build_object('event_type','fga.tuple.write','payload',jsonb_build_object(
    'user',(p_request->>'member_type')||':'||(p_request->>'member_id'),'relation','member','object','group:'||(p_request->>'group_id')))));
 END IF;
 -- После clock только private frozen data: ни нового nextval, ни business
 -- SELECT/FOR SHARE, ни fallback. Тот же decision stamp у Go и actual origin.
 IF n>p_rows THEN RAISE EXCEPTION 'group addition selection budget exceeded' USING ERRCODE='54000';END IF;
 PERFORM kaname._authority_sequence_bind_v3(selected,added_at);
 logical_rows:=n;logical_reads:=1;RETURN NEXT;
END $$;

CREATE FUNCTION kaname._authority_group_add_row_v3(p_table text,p_op text,p_old jsonb,p_new jsonb) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb; frozen jsonb; state jsonb; expected jsonb;
BEGIN
 program:=kaname._authority_group_add_program_v3();IF program IS NULL THEN RETURN false;END IF;
 frozen:=program->'frozen';state:=program->'command_state';
 IF program->'selected'='null'::jsonb OR frozen->>'reference_valid'<>'true' THEN
  RAISE EXCEPTION 'group addition body not finalized or reference invalid' USING ERRCODE='42501';END IF;
 CASE p_table
 WHEN 'group_members' THEN
  expected:=(frozen->'member_template')||jsonb_build_object('added_at',(program->>'decision_at')::timestamptz);
  IF p_op<>'INSERT' OR p_old IS NOT NULL OR p_new IS DISTINCT FROM expected OR state->>'member_attempted'<>'false' THEN
   RAISE EXCEPTION 'group addition member row or multiplicity differs' USING ERRCODE='42501';END IF;
  UPDATE pg_temp.kaname_group_add_command SET member_attempted=true WHERE singleton;
 WHEN 'fga_outbox' THEN
  IF p_op<>'INSERT' OR state->>'member_attempted'<>'true'
   OR (frozen->>'duplicate'='false' AND state->>'member_inserted'<>'true')
   OR state->>'fold_done'<>'false'
   OR NOT EXISTS(SELECT 1 FROM pg_temp.kaname_authority_sequence_effects e
    WHERE e.nonce=(program->>'nonce')::uuid AND e.table_name='fga_outbox' AND e.selected AND e.claimed AND NOT e.consumed
     AND e.reserved_id=(p_new->>'id')::bigint AND e.row_value=p_new-'id') THEN
   RAISE EXCEPTION 'group addition FGA row or order differs' USING ERRCODE='42501';END IF;
 WHEN 'relation_fact' THEN
  IF state->>'fold_active'<>'true' OR pg_trigger_depth()<1
   OR NOT ((p_op='INSERT' AND p_old IS NULL AND p_new=frozen->'fact_insert' AND state->>'fact_attempted'='false')
    OR (p_op='UPDATE' AND p_old=frozen->'old_fact' AND p_new=frozen->'fact_final' AND p_old IS DISTINCT FROM p_new
     AND state->>'fact_attempted'='true' AND state->>'fact_updated'='false')) THEN
   RAISE EXCEPTION 'group addition fact outside actual fold' USING ERRCODE='42501';END IF;
  IF p_op='INSERT' THEN UPDATE pg_temp.kaname_group_add_command SET fact_attempted=true WHERE singleton;
  ELSE UPDATE pg_temp.kaname_group_add_command SET fact_updated=true WHERE singleton;END IF;
 ELSE RAISE EXCEPTION 'group addition attempted another mutation family' USING ERRCODE='42501';END CASE;
 RETURN true;
END $$;

CREATE FUNCTION kaname._authority_group_add_statement_v3(p_table text,p_op text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;
BEGIN
 program:=kaname._authority_group_add_program_v3();IF program IS NULL THEN RETURN false;END IF;
 IF program->'selected'='null'::jsonb OR program#>>'{frozen,reference_valid}'<>'true'
 OR NOT ((p_table='group_members' AND p_op='INSERT' AND program#>>'{command_state,member_attempted}'='false')
  OR (p_table='fga_outbox' AND p_op='INSERT' AND program#>>'{command_state,member_attempted}'='true' AND program#>>'{command_state,fold_done}'='false')
  OR (p_table='resource_journal' AND p_op='INSERT' AND pg_trigger_depth()>1 AND program#>>'{command_state,member_inserted}'='true')
  OR (p_table='relation_fact' AND p_op IN ('INSERT','UPDATE') AND program#>>'{command_state,fold_active}'='true' AND pg_trigger_depth()>=1)) THEN
  RAISE EXCEPTION 'group addition statement outside exact command' USING ERRCODE='42501';END IF;
 RETURN true;
END $$;

-- Вызывается только реальным FGA statement trigger: consumed ID уже записан
-- owner AFTER ROW guard. Прямой вызов/повтор не может объявить fold завершённым.
CREATE FUNCTION kaname.authority_group_add_fold_v3(p_event_type text,p_payload jsonb,p_created_at timestamptz) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb; row_value jsonb; old_row jsonb; changed integer; invoker oid;
BEGIN
 program:=kaname._authority_group_add_program_v3();IF program IS NULL THEN RETURN false;END IF;
 IF pg_trigger_depth()<1 OR program#>>'{command_state,fold_active}'<>'false' OR program#>>'{command_state,fold_done}'<>'false'
 OR NOT EXISTS(SELECT 1 FROM pg_temp.kaname_authority_sequence_effects e
  WHERE e.nonce=(program->>'nonce')::uuid AND e.table_name='fga_outbox' AND e.selected AND e.claimed AND e.consumed
   AND e.row_value=jsonb_build_object('event_type',p_event_type,'payload',p_payload,'created_at',p_created_at)) THEN
  RAISE EXCEPTION 'group addition fold lacks consumed actual FGA row' USING ERRCODE='42501';END IF;
 invoker:=(program->>'invoker_oid')::oid;
 IF NOT has_table_privilege(invoker,'kaname.relation_fact','INSERT') OR NOT has_table_privilege(invoker,'kaname.relation_fact','UPDATE')
 OR NOT has_table_privilege(invoker,'kaname.relation_fact','SELECT') THEN
  RAISE EXCEPTION 'group addition original fold privileges absent' USING ERRCODE='42501';END IF;
 row_value:=program#>'{frozen,fact_insert}';old_row:=program#>'{frozen,old_fact}';
 UPDATE pg_temp.kaname_group_add_command SET fold_active=true WHERE singleton;
 -- Сохраняем и пустой/stale UPSERT: его BEFORE INSERT и statement UPDATE
 -- действительно выполняются в исходном fold. Только row images уже frozen.
 INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject,source_version,created_at,condition_name,condition_params)
  SELECT r.object_type,r.object_id,r.relation,r.subject,r.source_version,r.created_at,r.condition_name,r.condition_params
  FROM jsonb_populate_record(NULL::kaname.relation_fact,row_value) r
  ON CONFLICT (object_type,object_id,relation,subject) DO UPDATE
   SET source_version=EXCLUDED.source_version,condition_name=EXCLUDED.condition_name
   WHERE relation_fact.source_version<EXCLUDED.source_version;
 GET DIAGNOSTICS changed=ROW_COUNT;
 -- Скобки удерживают внутренний THEN в CASE, отдельно от THEN оператора IF.
 IF changed IS DISTINCT FROM (CASE WHEN old_row IS DISTINCT FROM program#>'{frozen,fact_final}' THEN 1 ELSE 0 END) THEN
  RAISE EXCEPTION 'group addition exact fold was not applied' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_group_add_command SET fold_active=false,fold_done=true WHERE singleton;
 RETURN true;
END $$;

CREATE FUNCTION kaname.authority_group_add_subject_id_v3() RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb; proof jsonb; invoker oid; identifier bigint;
BEGIN
 SELECT oid INTO STRICT invoker FROM pg_catalog.pg_roles WHERE rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
 IF NOT has_sequence_privilege(invoker,'kaname.subject_change_outbox_id_seq','USAGE,UPDATE') THEN
  RAISE EXCEPTION 'subject change default lacks original sequence privilege' USING ERRCODE='42501';END IF;
 program:=kaname._authority_group_add_program_v3();
 IF program IS NULL THEN RETURN nextval('kaname.subject_change_outbox_id_seq');END IF;
 IF NOT has_table_privilege(invoker,'kaname.subject_change_outbox','INSERT')
 OR program#>>'{command_state,fold_done}'<>'true' OR program#>>'{command_state,subject_claimed}'<>'false'
 OR program#>>'{frozen,reference_valid}'<>'true' OR program->'selected'='null'::jsonb THEN
  RAISE EXCEPTION 'group addition subject claim order or privilege invalid' USING ERRCODE='42501';END IF;
 identifier:=(program#>>'{frozen,subject,id}')::bigint;
 PERFORM kaname._authority_resource_preheld_key_v2(1262569301,identifier::text,true);
 UPDATE pg_temp.kaname_group_add_command SET subject_claimed=true WHERE singleton;
 RETURN identifier;
END $$;

CREATE FUNCTION kaname._authority_group_add_subject_v3(p_phase text,p_op text,p_row jsonb) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;
BEGIN
 program:=kaname._authority_group_add_program_v3();IF program IS NULL THEN RETURN false;END IF;
 IF p_phase NOT IN ('before','after') OR p_phase IS NULL OR p_op<>'INSERT'
 OR program#>>'{command_state,fold_done}'<>'true' OR program#>>'{command_state,subject_claimed}'<>'true'
 OR program#>>'{command_state,subject_done}'<>'false' OR p_row IS DISTINCT FROM program#>'{frozen,subject}' THEN
  RAISE EXCEPTION 'group addition subject row or multiplicity differs' USING ERRCODE='42501';END IF;
 PERFORM kaname._authority_resource_preheld_key_v2(1262569301,p_row->>'id',true);
 IF p_phase='after' THEN UPDATE pg_temp.kaname_group_add_command SET subject_done=true WHERE singleton;END IF;
 RETURN true;
END $$;

CREATE FUNCTION kaname._authority_group_add_complete_v3() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;
BEGIN
 program:=kaname._authority_group_add_program_v3();IF program IS NULL THEN RETURN;END IF;
 IF program#>>'{frozen,reference_valid}'<>'true' OR program->'selected'='null'::jsonb
 OR program#>>'{command_state,member_attempted}'<>'true'
 OR (program#>>'{command_state,member_inserted}')::boolean IS DISTINCT FROM (NOT (program#>>'{frozen,duplicate}')::boolean)
 OR program#>>'{command_state,fold_active}'<>'false' OR program#>>'{command_state,fold_done}'<>'true'
 OR program#>>'{command_state,fact_attempted}'<>'true'
 OR (program#>>'{command_state,fact_updated}')::boolean IS DISTINCT FROM
  (program#>'{frozen,old_fact}'<>'null'::jsonb AND program#>'{frozen,old_fact}' IS DISTINCT FROM program#>'{frozen,fact_final}')
 OR program#>>'{command_state,subject_claimed}'<>'true' OR program#>>'{command_state,subject_done}'<>'true' THEN
  RAISE EXCEPTION 'group addition required command incomplete' USING ERRCODE='42501';END IF;
END $$;

CREATE OR REPLACE FUNCTION kaname.relation_fact_fold_row(
    p_event_type text, p_payload jsonb, p_created_at timestamptz) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_delete_through timestamptz;
    v_user      text := p_payload ->> 'user';
    v_object    text := p_payload ->> 'object';
    -- Версия ВЛАДЕЛЬЦА. Есть только у строки, которую владелец упорядочил сам.
    v_owner     text := p_payload ->> 'source_version';
    v_version   timestamptz;
    v_relations text[];
    v_relation  text;
    v_type      text;
    v_id        text;
    v_colon     int;
    -- Условие, которое модель объявляет на прямом списке этого отношения для
    -- типа субъекта строки (`[user with mfa_fresh]`); пусто — безусловно.
    v_condition text;
    -- Хранимый субъект строки снятия (п. 4 шапки миграции kaname#829).
    v_stored    text;
BEGIN
    -- Signed Resource исполняет только private final программу без позднего
    -- holder lookup/clock/lock; legacy семантика ниже сохранена дословно.
    IF kaname.authority_group_add_fold_v3(p_event_type,p_payload,p_created_at) THEN RETURN;END IF;
    IF kaname.authority_resource_fold_body_v2(p_event_type,p_payload,p_created_at) THEN RETURN;END IF;
    -- Набор ВЫИГРЫВАЕТ у скаляра: на выдаче набора присутствуют оба поля, и
    -- скаляр там — эхо для пода прежнего выпуска, а не весь предмет строки.
    IF jsonb_array_length(coalesce(p_payload -> 'relations', '[]'::jsonb)) > 0 THEN
        -- Отношения набора — в ОБЩЕМ порядке, а не в порядке писателя: строка
        -- факта ключуется отношением, и два набора одного субъекта на одном
        -- объекте, перечисленные встречно, брали бы их блокировки встречно.
        SELECT array_agg(value ORDER BY value COLLATE "C") INTO v_relations
          FROM jsonb_array_elements_text(p_payload -> 'relations') AS value;
    ELSIF p_payload ->> 'relation' IS NOT NULL THEN
        v_relations := ARRAY[p_payload ->> 'relation'];
    END IF;

    IF v_user IS NULL OR v_relations IS NULL OR v_object IS NULL THEN
        RAISE EXCEPTION
            'fga_outbox: строка без user/relation/object (%). Прямой факт складывается из этого журнала, и строка, которую нельзя спроецировать, дала бы движку право, о котором своя БД не знает.',
            p_payload;
    END IF;

    -- Порядок строки. У строки, упорядоченной владельцем, его задаёт версия
    -- владельца: метка журнала — момент НАЧАЛА транзакции службы, и у снятия,
    -- начавшего транзакцию раньше открытия, она оказалась бы старше того, что
    -- снятие обязано снять. Неразбираемая версия роняет строку, а не
    -- подменяется меткой: молчаливая подмена вернула бы ровно тот порядок, от
    -- которого поле защищает.
    v_version := coalesce(v_owner::timestamptz, p_created_at);

    -- Глагол выводится из выдачи и копией не хранится (см. 0098). Набор из
    -- одних глаголов выходит здесь — до разбора объекта, как и одиночный.
    --
    -- ИСКЛЮЧЕНИЕ ОДНО: строка, упорядоченная владельцем, — публикация для
    -- анонимного чтения. Её не выводит ни одна выдача, и отброшенная здесь, она
    -- не существовала бы нигде (kaname#107).
    IF v_owner IS NULL THEN
        v_relations := ARRAY(SELECT r FROM unnest(v_relations) AS r WHERE r NOT LIKE 'v\_%');
        IF array_length(v_relations, 1) IS NULL THEN
            RETURN;
        END IF;
    END IF;

    v_colon := position(':' in v_object);
    IF v_colon <= 1 OR v_colon = length(v_object) THEN
        RAISE EXCEPTION
            'fga_outbox: объект % не имеет формы "<тип>:<идентификатор>" — спроецировать прямой факт нельзя.',
            v_object;
    END IF;
    v_type := substr(v_object, 1, v_colon - 1);
    v_id   := substr(v_object, v_colon + 1);

    IF v_type LIKE '%.%' THEN
        RAISE EXCEPTION
            'fga_outbox: тип объекта % назван словарём каталога. Вопрос о доступе приходит словарём модели прав, и такая строка не совпала бы ни с одним вопросом.',
            v_type;
    END IF;

    FOREACH v_relation IN ARRAY v_relations LOOP
        IF p_event_type = 'fga.tuple.write' THEN
            -- Условие прикладывает ПИСАТЕЛЬ, и только он: факт человека на
            -- условном отношении без условия значил бы безусловный допуск там,
            -- где модель объявляет допуск лишь при выполненном условии.
            -- Перечень — дословно `with`-записи канонической модели; гейт
            -- `TestConditionedRelationHasAProducer` сверяет его с моделью в обе
            -- стороны (запись модели без строки и строка без записи модели —
            -- находки).
            SELECT c.condition_name INTO v_condition
              FROM (VALUES
                    ('compute_instance', 'console', 'user', 'mfa_fresh'),
                    ('compute_instance', 'ssh',     'user', 'mfa_fresh')
                   ) AS c(object_type, relation, subject_type, condition_name)
             WHERE c.object_type = v_type AND c.relation = v_relation
               AND c.subject_type = split_part(v_user, ':', 1);

            INSERT INTO kaname.relation_fact
                   (object_type, object_id, relation, subject, source_version, created_at, condition_name)
            VALUES (v_type, v_id, v_relation, v_user, v_version, now(), coalesce(v_condition, ''))
            ON CONFLICT (object_type, object_id, relation, subject) DO UPDATE
               SET source_version = EXCLUDED.source_version,
                   condition_name = EXCLUDED.condition_name
             WHERE relation_fact.source_version < EXCLUDED.source_version;
        ELSIF p_event_type = 'fga.tuple.delete' THEN
            -- Снятие с подстановкой прежнего писателя снимает строку, в которую
            -- переезд (п. 3) перенёс то, что этот писатель когда-то положил:
            -- перевод тот же, что у переписи, по отношению (п. 4 шапки).
            v_stored := v_user;
            IF v_user = 'user:*' THEN
                v_stored := CASE WHEN v_relation = 'v_get' THEN 'system_class:anonymous'
                                 ELSE 'system_class:authenticated' END;
            END IF;
            -- Факт, выведенный выдачей (строка без версии владельца), снимается
            -- лишь тогда, когда его не держит больше НИКТО (п. 2 шапки). Сперва
            -- замок строки факта: снятие ждёт любого, кто держит её незафиксированной
            -- (выдачу, свёрнутую в той же строке, второе снятие), и вопрос «держит
            -- ли кто-то ещё» задаётся уже после его коммита, свежим снимком.
            -- Новый typed mixed-set также проверяет держателей legacy строки;
            -- флаг кладёт только внутренний combined-delete, не запрос клиента.
            IF v_owner IS NULL OR p_payload->'protect_holders' = 'true'::jsonb OR EXISTS (
                   SELECT 1 FROM kaname.resource_registration_pointer rp
                    WHERE rp.object_type=v_type AND rp.object_id=v_id AND rp.relation=v_relation AND rp.subject=v_stored) THEN
                PERFORM 1 FROM kaname.relation_fact
                 WHERE object_type = v_type AND object_id = v_id
                   AND relation = v_relation AND subject = v_stored
                   FOR UPDATE;
                IF NOT FOUND THEN
                    CONTINUE;
                END IF;
                IF EXISTS (
                       SELECT 1
                         FROM kaname.access_binding_emitted_tuples et
                         JOIN kaname.access_bindings ab ON ab.id = et.binding_id
                        WHERE et.object = v_object AND et.relation = v_relation
                          AND et.fga_user = v_stored AND ab.status = 'ACTIVE')
                   OR EXISTS (SELECT 1 FROM kaname.resource_registration_pointer rp
                               WHERE rp.object_type=v_type AND rp.object_id=v_id AND rp.relation=v_relation
                                 AND rp.subject=v_stored AND rp.active)
                   OR (v_type = 'cluster' AND v_relation = 'system_admin' AND EXISTS (
                       SELECT 1
                         FROM kaname.cluster_admin_grants g
                        WHERE g.cluster_id = v_id
                          AND g.subject_type || ':' || g.subject_id = v_stored
                          AND (g.granted_until IS NULL OR g.granted_until > clock_timestamp())))
                THEN
                    CONTINUE;
                END IF;
            END IF;
            v_delete_through := NULL;
            IF v_owner IS NULL AND v_relation IN ('project','parent','owner') THEN
                -- Отдельный свежий RC statement ПОСЛЕ fact lock и held read.
                -- Без обратного замка receipt: registrar меняет её ДО факта.
                SELECT delete_through INTO v_delete_through
                  FROM kaname.resource_registration_retirement
                 WHERE object_type=v_type AND object_id=v_id
                   AND relation=v_relation AND subject=v_stored;
            END IF;
            -- У exact named tuple последний держатель может уйти меткой AB,
            -- отличной от шкалы владельца. После fresh held-check снимаем его
            -- без произвольного повышения надгробия; stale owner не проходит
            -- сохранённую версию claim. Для legacy tuple сравнение прежнее.
            DELETE FROM kaname.relation_fact
             WHERE object_type = v_type AND object_id = v_id
               AND relation = v_relation AND subject = v_stored
               AND (source_version <= v_version
                    OR (v_owner IS NULL AND v_delete_through IS NOT NULL AND source_version <= v_delete_through) OR EXISTS (
                    SELECT 1 FROM kaname.resource_registration_pointer rp
                     WHERE rp.object_type=v_type AND rp.object_id=v_id
                       AND rp.relation=v_relation AND rp.subject=v_stored
                       AND NOT rp.active
                       AND (v_owner IS NULL OR rp.source_version <= v_version)));
        END IF;
    END LOOP;
    RETURN;
END $$;

CREATE OR REPLACE FUNCTION kaname.authority_subject_change_id_guard_v2() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;matches integer;
BEGIN
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME<>'subject_change_outbox' OR TG_WHEN<>'BEFORE'
 OR TG_LEVEL<>'ROW' OR TG_OP NOT IN ('INSERT','UPDATE') THEN
  RAISE EXCEPTION 'invalid subject_change ID guard context' USING ERRCODE='42501';END IF;
 IF kaname._authority_group_add_subject_v3('before',TG_OP,to_jsonb(NEW)) THEN RETURN NEW;END IF;
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NULL THEN PERFORM pg_advisory_xact_lock(1262569301,hashtext(NEW.id::text));RETURN NEW;END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Resource cannot update subject_change queue' USING ERRCODE='42501';END IF;
 PERFORM kaname._authority_resource_preheld_key_v2(1262569301,NEW.id::text,true);
 SELECT count(*) INTO matches FROM jsonb_array_elements(manifest#>'{registration_physical,subject_changes}') q
  WHERE q->'row'=to_jsonb(NEW) AND q->'command'=manifest->'object_command';
 IF matches<>1 OR coalesce((manifest->'consumed_subject_change_ids') @> jsonb_build_array(NEW.id),true) THEN
  RAISE EXCEPTION 'subject_change insert outside exact registration command' USING ERRCODE='42501';END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION kaname.authority_subject_change_applied_v2() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;
BEGIN
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME<>'subject_change_outbox' OR TG_WHEN<>'AFTER'
 OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' THEN RAISE EXCEPTION 'invalid subject_change applied context' USING ERRCODE='42501';END IF;
 IF kaname._authority_group_add_subject_v3('after',TG_OP,to_jsonb(NEW)) THEN RETURN NULL;END IF;
 manifest:=kaname._authority_producer_resource_v2();IF manifest IS NULL THEN RETURN NULL;END IF;
 IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(manifest#>'{registration_physical,subject_changes}') q
  WHERE q->'row'=to_jsonb(NEW) AND q->'command'=manifest->'object_command') THEN
  RAISE EXCEPTION 'unverified subject_change row applied' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_authority_resource_manifest SET consumed_subject_change_ids=array_append(consumed_subject_change_ids,NEW.id);
 RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION kaname.authority_subject_change_statement_guard_v2() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF kaname._authority_group_add_program_v3() IS NOT NULL THEN
  RAISE EXCEPTION 'group addition subject queue is append-only' USING ERRCODE='42501';END IF;
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME<>'subject_change_outbox' OR TG_WHEN<>'BEFORE'
 OR TG_LEVEL<>'STATEMENT' OR TG_OP NOT IN ('UPDATE','DELETE','TRUNCATE') THEN
  RAISE EXCEPTION 'invalid subject_change statement guard context' USING ERRCODE='42501';END IF;
 IF kaname._authority_producer_resource_v2() IS NOT NULL THEN
  RAISE EXCEPTION 'Resource subject_change queue is append-only exact program' USING ERRCODE='42501';END IF;
 RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION kaname._authority_resource_subject_change_wait_v2(p_count integer,p_reads integer)
RETURNS TABLE(reserved_ids jsonb,held_relations jsonb,held_advisory jsonb,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;invoker oid;table_id oid;sequence_id oid;identifier bigint;item record;
 ids jsonb:='[]'::jsonb;locks jsonb:='[]'::jsonb;relations jsonb;used integer:=5;i integer;present boolean;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource' OR proof->>'purpose' IS DISTINCT FROM 'participant'
 OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_finalized' IS DISTINCT FROM 'false'
 OR proof->>'consumer_profile' NOT IN ('resource_pending','resource_source_pending')
 OR current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'subject_change reservation requires pending Resource RC' USING ERRCODE='42501';END IF;
 IF p_count IS NULL OR p_count<1 OR p_count>100000 OR p_reads IS NULL OR p_reads<5+2*p_count OR p_reads>4096 THEN
  RAISE EXCEPTION 'subject_change reservation budget exceeded' USING ERRCODE='54000';END IF;
 invoker:=(proof->>'invoker_oid')::oid;table_id:='kaname.subject_change_outbox'::regclass;
 IF NOT has_table_privilege(invoker,table_id,'INSERT') THEN
  RAISE EXCEPTION 'subject_change INSERT privilege required' USING ERRCODE='42501';END IF;
 LOCK TABLE ONLY kaname.subject_change_outbox IN ROW EXCLUSIVE MODE;
 SELECT to_regclass(pg_get_serial_sequence('kaname.subject_change_outbox','id')) INTO sequence_id;
 IF sequence_id IS NULL OR sequence_id<>'kaname.subject_change_outbox_id_seq'::regclass
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=table_id AND a.attname='id'
  AND a.atttypid='bigint'::regtype AND a.attidentity='' AND NOT a.attisdropped)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid=table_id AND a.attname='id' AND pg_get_expr(d.adbin,d.adrelid)=$default$kaname.authority_group_add_subject_id_v3()$default$)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid=table_id OR inhparent=table_id) THEN
  RAISE EXCEPTION 'subject_change physical identity schema changed' USING ERRCODE='42501';END IF;
 -- Прежний INSERT serial вызывает nextval от invoker: owner helper сохраняет
 -- USAGE либо UPDATE sequence, не добавляя SELECT на неё.
 IF NOT (has_sequence_privilege(invoker,sequence_id,'USAGE') OR has_sequence_privilege(invoker,sequence_id,'UPDATE')) THEN
  RAISE EXCEPTION 'subject change sequence privilege required' USING ERRCODE='42501';END IF;
 -- nextval удерживает relation lock до конца всей TX даже при savepoint rollback.
 FOR i IN 1..p_count LOOP
  identifier:=nextval(sequence_id);used:=used+1;
  IF identifier<=0 THEN RAISE EXCEPTION 'invalid reserved subject_change ID' USING ERRCODE='P1034';END IF;
  ids:=ids||jsonb_build_array(identifier);
 END LOOP;
 -- Замки уникальности совместимы с legacy INSERT/переносом ID через trigger.
 -- Сортировка по фактическому advisory hash исключает inversion внутри набора.
 FOR item IN SELECT DISTINCT hashtext(v#>>'{}') h FROM jsonb_array_elements(ids) v ORDER BY h LOOP
  PERFORM pg_advisory_xact_lock(1262569301,item.h);
  locks:=locks||jsonb_build_array(jsonb_build_object('classid',1262569301,'objid',(item.h::bigint & 4294967295),
   'objsubid',2,'mode','ExclusiveLock'));
 END LOOP;
 FOR identifier IN SELECT (v#>>'{}')::bigint FROM jsonb_array_elements(ids) v LOOP
  used:=used+1;present:=false;
  SELECT true INTO present FROM ONLY kaname.subject_change_outbox q WHERE q.id=identifier FOR UPDATE;
  IF coalesce(present,false) THEN RAISE EXCEPTION 'reserved subject_change ID already exists' USING ERRCODE='P1034';END IF;
 END LOOP;
 relations:=jsonb_build_array(jsonb_build_object('oid',table_id,'mode','RowExclusiveLock'),
  jsonb_build_object('oid',sequence_id,'mode','RowExclusiveLock'));
 RETURN QUERY SELECT ids,relations,locks,used;
END $$;

ALTER TABLE kaname.subject_change_outbox ALTER COLUMN id SET DEFAULT kaname.authority_group_add_subject_id_v3();

CREATE FUNCTION kaname._authority_group_add_storage_v3() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM (VALUES
 ('_authority_group_add_program_v3()','jsonb',0,false,NULL),
 ('authority_group_add_prepare_v3(jsonb,integer,integer)','jsonb',3,false,ARRAY['p_request','p_rows','p_reads']::text[]),
 ('authority_group_add_finalize_v3(jsonb,integer,integer)','record',3,true,ARRAY['p_request','p_rows','p_reads','reference_valid','added_at','logical_rows','logical_reads']::text[]),
 ('_authority_group_add_row_v3(text,text,jsonb,jsonb)','boolean',4,false,ARRAY['p_table','p_op','p_old','p_new']::text[]),
 ('_authority_group_add_statement_v3(text,text)','boolean',2,false,ARRAY['p_table','p_op']::text[]),
 ('authority_group_add_fold_v3(text,jsonb,timestamptz)','boolean',3,false,ARRAY['p_event_type','p_payload','p_created_at']::text[]),
 ('authority_group_add_subject_id_v3()','bigint',0,false,NULL),
 ('_authority_group_add_subject_v3(text,text,jsonb)','boolean',3,false,ARRAY['p_phase','p_op','p_row']::text[]),
 ('_authority_group_add_complete_v3()','void',0,false,NULL),
 ('_authority_group_add_storage_v3()','boolean',0,false,NULL),
 ('relation_fact_fold_row(text,jsonb,timestamptz)','void',3,false,ARRAY['p_event_type','p_payload','p_created_at']::text[]),
 ('relation_fact_from_journal()','trigger',0,false,NULL),
 ('authority_subject_change_id_guard_v2()','trigger',0,false,NULL),
 ('authority_subject_change_applied_v2()','trigger',0,false,NULL),
 ('authority_subject_change_statement_guard_v2()','trigger',0,false,NULL)
 ) a(signature,result_type,nargs,returns_set,argnames)
 LEFT JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||a.signature)
 WHERE p.oid IS NULL OR p.prokind<>'f' OR p.prorettype<>a.result_type::regtype OR p.proretset<>a.returns_set
 OR p.proisstrict OR p.proleakproof OR p.proparallel<>'u' OR p.pronargs<>a.nargs OR p.pronargdefaults<>0 OR p.provariadic<>0
 OR p.proargnames IS DISTINCT FROM a.argnames
 OR p.prolang<>(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
 OR CASE WHEN a.returns_set THEN
  p.proargmodes IS DISTINCT FROM ARRAY['i','i','i','t','t','t','t']::"char"[]
  OR p.proallargtypes IS DISTINCT FROM ARRAY['jsonb'::regtype,'integer'::regtype,'integer'::regtype,'boolean'::regtype,'timestamptz'::regtype,'integer'::regtype,'integer'::regtype]::oid[]
 ELSE p.proargmodes IS NOT NULL OR p.proallargtypes IS NOT NULL END) THEN RETURN false;END IF;
 -- Actual relay и три subject hooks остаются прежними attachments.
 -- Полная shape исключает подмену BEFORE/AFTER, UPDATE OF id и transition table.
 IF EXISTS(SELECT 1 FROM (VALUES
  ('fga_outbox','relation_fact_00_native_batch','_authority_native_delete_batch_begin_v4()',4,ARRAY[]::text[],'journal_rows'::text),
  ('fga_outbox','relation_fact_zz_native_batch','_authority_native_delete_batch_end_v4()',4,ARRAY[]::text[],'journal_rows'::text),
  ('fga_outbox','relation_fact_follows_journal','relation_fact_from_journal()',4,ARRAY[]::text[],'journal_rows'::text),
  ('subject_change_outbox','authority_subject_change_id_guard_v2','authority_subject_change_id_guard_v2()',23,ARRAY['id']::text[],NULL::text),
  ('subject_change_outbox','authority_subject_change_applied_v2','authority_subject_change_applied_v2()',5,ARRAY[]::text[],NULL::text),
  ('subject_change_outbox','authority_subject_change_statement_guard_v2','authority_subject_change_statement_guard_v2()',58,ARRAY[]::text[],NULL::text)
 ) e(table_name,trigger_name,signature,trigger_type,columns,new_table)
 LEFT JOIN pg_catalog.pg_trigger t ON t.tgrelid=to_regclass('kaname.'||e.table_name) AND t.tgname=e.trigger_name
 WHERE t.oid IS NULL OR t.tgfoid<>to_regprocedure('kaname.'||e.signature)
 OR t.tgtype::integer<>e.trigger_type OR t.tgenabled<>'O' OR t.tgisinternal OR t.tgconstraint<>0
 OR t.tgdeferrable OR t.tginitdeferred OR t.tgqual IS NOT NULL OR t.tgnargs<>0 OR octet_length(t.tgargs)<>0
 OR t.tgoldtable IS NOT NULL OR t.tgnewtable::text IS DISTINCT FROM e.new_table
 OR ARRAY(SELECT a.attname::text FROM unnest(t.tgattr) WITH ORDINALITY x(num,pos)
  JOIN pg_catalog.pg_attribute a ON a.attrelid=t.tgrelid AND a.attnum=x.num AND NOT a.attisdropped ORDER BY x.pos) IS DISTINCT FROM e.columns
 OR (SELECT count(*) FROM pg_catalog.pg_trigger other WHERE other.tgfoid=t.tgfoid)<>1) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
  WHERE a.attrelid='kaname.subject_change_outbox'::regclass AND a.attname='id' AND NOT a.attisdropped
   AND a.atttypid='bigint'::regtype AND a.attidentity='' AND a.attgenerated=''
   AND pg_get_expr(d.adbin,d.adrelid)='kaname.authority_group_add_subject_id_v3()') THEN RETURN false;END IF;
 RETURN true;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_binding_epoch_changed() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE retained_proof jsonb;mirror_metadata jsonb;mirror_covered boolean;keys text[]; k text; manifest jsonb; image jsonb; metadata jsonb; resource_keys text[]; resource_roles text[];
BEGIN
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NOT NULL THEN
  IF TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'resource truncate denied' USING ERRCODE='42501'; END IF;
  resource_keys:=ARRAY[]::text[]; resource_roles:=ARRAY[]::text[];
  IF TG_OP<>'INSERT' THEN
   FOR image IN SELECT to_jsonb(o) FROM old_epoch_rows o LOOP
    metadata:=kaname._authority_resource_side_v2(manifest,TG_TABLE_NAME,TG_OP,'old',image);
    resource_keys:=resource_keys||kaname._authority_resource_key_array_v2(metadata->'binding_epoch_write_scopes',true);
    resource_roles:=resource_roles||kaname._authority_resource_key_array_v2(metadata->'deferred_carrier_roles');
    SELECT coalesce(array_agg(DISTINCT x),ARRAY[]::text[]) INTO resource_keys FROM unnest(resource_keys) x;
    SELECT coalesce(array_agg(DISTINCT x),ARRAY[]::text[]) INTO resource_roles FROM unnest(resource_roles) x;
   END LOOP;
  END IF;
  IF TG_OP<>'DELETE' THEN
   FOR image IN SELECT to_jsonb(n) FROM new_epoch_rows n LOOP
    metadata:=kaname._authority_resource_side_v2(manifest,TG_TABLE_NAME,TG_OP,'new',image);
    resource_keys:=resource_keys||kaname._authority_resource_key_array_v2(metadata->'binding_epoch_write_scopes',true);
    resource_roles:=resource_roles||kaname._authority_resource_key_array_v2(metadata->'deferred_carrier_roles');
    SELECT coalesce(array_agg(DISTINCT x),ARRAY[]::text[]) INTO resource_keys FROM unnest(resource_keys) x;
    SELECT coalesce(array_agg(DISTINCT x),ARRAY[]::text[]) INTO resource_roles FROM unnest(resource_roles) x;
   END LOOP;
  END IF;
  FOR k IN SELECT DISTINCT x COLLATE "C" FROM unnest(resource_keys) x ORDER BY 1 LOOP
   IF NOT ((manifest->'binding_epoch_write_scopes') ? k) THEN
    RAISE EXCEPTION 'resource epoch write was not prepared' USING ERRCODE='42501';
   END IF;
   PERFORM kaname._authority_resource_preheld_key_v2(1262569297,k,true);
   -- Ни INSERT, ни повторного FOR UPDATE после final clock.
   UPDATE kaname.authority_binding_epoch SET revision=revision+1 WHERE scope=k;
   IF NOT FOUND THEN RAISE EXCEPTION 'resource prepared epoch missing' USING ERRCODE='40001'; END IF;
  END LOOP;
  RETURN NULL;
 END IF;
 -- Для exact prepared mirror member/ledger transition epoch keys уже
 -- удерживаются. Ни carrier lookup, ни открытие нового ключа после часов.
 IF TG_TABLE_NAME IN ('access_binding_target_members','access_binding_emitted_tuples') AND TG_OP<>'TRUNCATE' THEN
  mirror_metadata:=kaname._authority_binding_mirror_store_v3();
  IF mirror_metadata IS NOT NULL THEN
   IF mirror_metadata->>'final_clock' IS NULL OR mirror_metadata->>'final_clock' IS DISTINCT FROM mirror_metadata->>'epoch_clock'
   OR mirror_metadata->>'final_clock' IS DISTINCT FROM (kaname.authority_protocol_attestation()->>'decision_at') THEN
    RAISE EXCEPTION 'binding mirror epoch statement lacks final proof' USING ERRCODE='42501';END IF;
   mirror_covered:=true;
   IF TG_OP<>'DELETE' THEN
    SELECT NOT EXISTS(SELECT 1 FROM new_epoch_rows n WHERE NOT EXISTS(SELECT 1 FROM pg_temp.kaname_binding_mirror_images i
     WHERE i.table_name=TG_TABLE_NAME AND i.new_hash=sha256(convert_to(to_jsonb(n)::text,'UTF8')) AND i.new_image=to_jsonb(n))) INTO mirror_covered;
   END IF;
   IF TG_OP<>'INSERT' AND mirror_covered THEN
    SELECT NOT EXISTS(SELECT 1 FROM old_epoch_rows o WHERE NOT EXISTS(SELECT 1 FROM pg_temp.kaname_binding_mirror_images i
     WHERE i.table_name=TG_TABLE_NAME AND i.old_hash=sha256(convert_to(to_jsonb(o)::text,'UTF8')) AND i.old_image=to_jsonb(o))) INTO mirror_covered;
   END IF;
   IF mirror_covered THEN
    -- Пустые ON CONFLICT transitions не являются изменением поколения.
    IF TG_OP='INSERT' THEN IF NOT EXISTS(SELECT 1 FROM new_epoch_rows) THEN RETURN NULL;END IF;
    ELSIF TG_OP='DELETE' THEN IF NOT EXISTS(SELECT 1 FROM old_epoch_rows) THEN RETURN NULL;END IF;
    ELSE IF NOT EXISTS(SELECT 1 FROM old_epoch_rows) AND NOT EXISTS(SELECT 1 FROM new_epoch_rows) THEN RETURN NULL;END IF;END IF;
    UPDATE kaname.authority_binding_epoch SET revision=revision+1 WHERE scope IN (SELECT jsonb_array_elements_text(mirror_metadata->'accounts'));
    IF NOT FOUND THEN RAISE EXCEPTION 'binding prepared epoch disappeared' USING ERRCODE='40001';END IF;
    RETURN NULL;
   END IF;
  END IF;
 END IF;
 -- Unsigned RR может предшествовать compatibility barrier. Поэтому retained
 -- predicate всегда инвалидирует ROOT, даже если snapshot не видит OLD owner.
 IF TG_TABLE_NAME='resource_registration_scope' THEN
  retained_proof:=kaname.authority_protocol_attestation();
  -- Generation1 ResourceObjectParticipant заранее входит GLOBAL/typed. Свежая
  -- attestation удостоверяет owner contract=1 и удерживаемые root/compatibility
  -- locks; caller flag не участвует. Остальные signed writers требуют manifest.
  IF retained_proof IS NOT NULL AND (
   retained_proof->>'writer_contract' IS DISTINCT FROM '1'
   OR retained_proof->>'kind' IS DISTINCT FROM 'resource'
   OR retained_proof->>'purpose' IS DISTINCT FROM 'participant'
   OR retained_proof->>'mode' IS DISTINCT FROM 'global'
   OR retained_proof->>'consumer_profile' IS DISTINCT FROM 'typed'
   OR TG_OP NOT IN ('INSERT','UPDATE','DELETE')) THEN
   RAISE EXCEPTION 'signed retained write requires prepared resource manifest' USING ERRCODE='42501';
  END IF;
  IF TG_OP='INSERT' THEN
   IF NOT EXISTS(SELECT 1 FROM new_epoch_rows) THEN RETURN NULL;END IF;
  ELSIF TG_OP='DELETE' THEN
   IF NOT EXISTS(SELECT 1 FROM old_epoch_rows) THEN RETURN NULL;END IF;
  ELSIF TG_OP='UPDATE' THEN
   IF NOT EXISTS(SELECT 1 FROM old_epoch_rows) AND NOT EXISTS(SELECT 1 FROM new_epoch_rows) THEN RETURN NULL;END IF;
  END IF;
  UPDATE kaname.authority_binding_epoch SET revision=revision+1 WHERE scope='';
  IF NOT FOUND THEN RAISE EXCEPTION 'binding root epoch missing' USING ERRCODE='40001';END IF;
  RETURN NULL;
 END IF;
 -- Transition tables принадлежат executor этого statement, не search_path.
 -- По одному bump на distinct OLD+NEW account на statement, не на ledger row.
 -- Target-member scope читает только binding и optional group coordinate.
 -- C сохраняет byte-distinct identifiers; default повторяет JSON text predicate.
 -- Оба MATERIALIZED ограничивают STABLE вычисление одним вызовом на dependency.
 IF TG_TABLE_NAME='access_binding_target_members' AND TG_OP IN ('INSERT','UPDATE','DELETE') THEN
  IF TG_OP='UPDATE' THEN
   WITH dependencies AS MATERIALIZED (
    SELECT DISTINCT d.binding_id,d.object_type,d.group_object_id FROM (
    SELECT o.binding_id COLLATE "C" AS binding_id,o.object_type COLLATE "C" AS object_type,
     (CASE WHEN o.object_type COLLATE "default"='iam.group' THEN o.object_id END) COLLATE "C" AS group_object_id
    FROM old_epoch_rows o
    UNION ALL
    SELECT n.binding_id COLLATE "C" AS binding_id,n.object_type COLLATE "C" AS object_type,
     (CASE WHEN n.object_type COLLATE "default"='iam.group' THEN n.object_id END) COLLATE "C" AS group_object_id
    FROM new_epoch_rows n
    ) d
   ), scopes AS MATERIALIZED (
    SELECT kaname.authority_binding_epoch_scope(TG_TABLE_NAME,
     pg_catalog.jsonb_build_object('binding_id',d.binding_id,'object_type',d.object_type,'object_id',d.group_object_id)) AS x
    FROM dependencies d
   )
   SELECT pg_catalog.array_agg(DISTINCT x ORDER BY x) INTO keys FROM scopes;
  ELSIF TG_OP='INSERT' THEN
   WITH dependencies AS MATERIALIZED (
    SELECT DISTINCT d.binding_id,d.object_type,d.group_object_id FROM (
    SELECT n.binding_id COLLATE "C" AS binding_id,n.object_type COLLATE "C" AS object_type,
     (CASE WHEN n.object_type COLLATE "default"='iam.group' THEN n.object_id END) COLLATE "C" AS group_object_id
    FROM new_epoch_rows n
    ) d
   ), scopes AS MATERIALIZED (
    SELECT kaname.authority_binding_epoch_scope(TG_TABLE_NAME,
     pg_catalog.jsonb_build_object('binding_id',d.binding_id,'object_type',d.object_type,'object_id',d.group_object_id)) AS x
    FROM dependencies d
   )
   SELECT pg_catalog.array_agg(DISTINCT x ORDER BY x) INTO keys FROM scopes;
  ELSE
   WITH dependencies AS MATERIALIZED (
    SELECT DISTINCT d.binding_id,d.object_type,d.group_object_id FROM (
    SELECT o.binding_id COLLATE "C" AS binding_id,o.object_type COLLATE "C" AS object_type,
     (CASE WHEN o.object_type COLLATE "default"='iam.group' THEN o.object_id END) COLLATE "C" AS group_object_id
    FROM old_epoch_rows o
    ) d
   ), scopes AS MATERIALIZED (
    SELECT kaname.authority_binding_epoch_scope(TG_TABLE_NAME,
     pg_catalog.jsonb_build_object('binding_id',d.binding_id,'object_type',d.object_type,'object_id',d.group_object_id)) AS x
    FROM dependencies d
   )
   SELECT pg_catalog.array_agg(DISTINCT x ORDER BY x) INTO keys FROM scopes;
  END IF;
 ELSIF TG_OP='UPDATE' THEN
  SELECT pg_catalog.array_agg(DISTINCT x ORDER BY x) INTO keys FROM (
   SELECT kaname.authority_binding_epoch_scope(TG_TABLE_NAME,pg_catalog.to_jsonb(o)) x FROM old_epoch_rows o
   UNION SELECT kaname.authority_binding_epoch_scope(TG_TABLE_NAME,pg_catalog.to_jsonb(n)) FROM new_epoch_rows n) s;
 ELSIF TG_OP='INSERT' THEN
  SELECT pg_catalog.array_agg(DISTINCT kaname.authority_binding_epoch_scope(TG_TABLE_NAME,pg_catalog.to_jsonb(n)) ORDER BY kaname.authority_binding_epoch_scope(TG_TABLE_NAME,pg_catalog.to_jsonb(n))) INTO keys FROM new_epoch_rows n;
 ELSIF TG_OP='DELETE' THEN
  SELECT pg_catalog.array_agg(DISTINCT kaname.authority_binding_epoch_scope(TG_TABLE_NAME,pg_catalog.to_jsonb(o)) ORDER BY kaname.authority_binding_epoch_scope(TG_TABLE_NAME,pg_catalog.to_jsonb(o))) INTO keys FROM old_epoch_rows o;
 ELSE keys:=ARRAY['']::text[];
 END IF;
 IF keys IS NULL THEN RETURN NULL; END IF;
 -- Глобальная строка shared для account writes: разные accounts не конфликтуют.
 -- Global source change конфликтует с любым apply snapshot.
 IF ''=ANY(keys) THEN
  UPDATE kaname.authority_binding_epoch SET revision=revision+1 WHERE scope='';
 ELSE
  PERFORM scope FROM kaname.authority_binding_epoch WHERE scope='' FOR KEY SHARE;
 END IF;
 FOREACH k IN ARRAY keys LOOP
  IF k<>'' THEN INSERT INTO kaname.authority_binding_epoch(scope,revision) VALUES(k,1)
   ON CONFLICT(scope) DO UPDATE SET revision=kaname.authority_binding_epoch.revision+1; END IF;
 END LOOP;
 RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION kaname.authority_binding_epoch_lock(p_accounts text[],p_expected jsonb) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; actual jsonb; at_time timestamptz; mirror_snapshot jsonb;
BEGIN
 IF p_expected IS NULL OR pg_catalog.jsonb_typeof(p_expected)<>'object' THEN RAISE EXCEPTION 'binding epoch snapshot is absent' USING ERRCODE='40001'; END IF;
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL THEN RAISE EXCEPTION 'binding apply requires participant entry' USING ERRCODE='42501'; END IF;
 IF proof->>'purpose' IS DISTINCT FROM 'participant' THEN RAISE EXCEPTION 'binding apply requires ordinary participant' USING ERRCODE='42501'; END IF;
 -- Общий порядок actual ROW locks: policy ROOT/typed keys → Binding ROOT/accounts.
 -- Owner snapshot проверяется до первого ожидания; caller не выбирает policy set.
 IF proof->>'kind'='binding' AND to_regclass('pg_temp.kaname_binding_sequence_snapshot') IS NOT NULL THEN
  mirror_snapshot:=kaname._authority_binding_stage_snapshot_v3();
  IF mirror_snapshot->'mirror' IS NOT NULL AND mirror_snapshot->'mirror'<>'null'::jsonb THEN
   IF p_accounts IS NULL OR cardinality(p_accounts)=0
   OR EXISTS(SELECT 1 FROM unnest(p_accounts) a WHERE a IS NULL OR a='')
   OR proof->>'mode' IS DISTINCT FROM 'accounts'
   OR proof->'accounts' IS DISTINCT FROM to_jsonb(p_accounts)
   OR mirror_snapshot->'accounts' IS DISTINCT FROM to_jsonb(p_accounts)
   OR mirror_snapshot->'epochs' IS DISTINCT FROM p_expected
   OR (mirror_snapshot->>'consumed' IS DISTINCT FROM 'false'
    AND to_regclass('pg_temp.kaname_binding_mirror_policy_receipt') IS NULL) THEN
    RAISE EXCEPTION 'binding early policy footprint differs from owner stage' USING ERRCODE='42501';END IF;
   PERFORM kaname._authority_binding_mirror_policy_prepare_v3(mirror_snapshot);
  END IF;
 END IF;
 IF p_accounts IS NULL THEN
  IF proof->>'mode' IS DISTINCT FROM 'global' THEN RAISE EXCEPTION 'binding global epoch requires global entry' USING ERRCODE='42501'; END IF;
  PERFORM scope FROM kaname.authority_binding_epoch WHERE scope='' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'binding epochs are uninitialized' USING ERRCODE='40001'; END IF;
 ELSE
  IF pg_catalog.cardinality(p_accounts)=0 OR EXISTS(SELECT 1 FROM pg_catalog.unnest(p_accounts) a WHERE a IS NULL OR a='') THEN RAISE EXCEPTION 'invalid binding epoch scope'; END IF;
  IF proof->>'mode'='accounts' AND NOT (proof->'accounts') @> pg_catalog.to_jsonb(p_accounts) THEN RAISE EXCEPTION 'epoch accounts exceed participant scope' USING ERRCODE='42501'; END IF;
  PERFORM scope FROM kaname.authority_binding_epoch WHERE scope='' FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'binding epochs are uninitialized' USING ERRCODE='40001'; END IF;
  PERFORM scope FROM kaname.authority_binding_epoch WHERE scope=ANY(p_accounts) ORDER BY scope FOR SHARE;
  IF (SELECT count(*) FROM kaname.authority_binding_epoch WHERE scope=ANY(p_accounts))<>(SELECT count(DISTINCT a) FROM pg_catalog.unnest(p_accounts) a) THEN RAISE EXCEPTION 'binding epoch disappeared' USING ERRCODE='40001'; END IF;
 END IF;
 actual:=kaname.authority_binding_epoch_read(p_accounts);
 IF actual IS DISTINCT FROM p_expected THEN RAISE EXCEPTION 'binding stage changed' USING ERRCODE='40001'; END IF;
 at_time:=pg_catalog.clock_timestamp();
 UPDATE pg_temp.kaname_authority_attestation SET decision_at=at_time;
 PERFORM kaname._authority_binding_mirror_epoch_v3(p_accounts,p_expected,at_time);
 RETURN at_time;
END $$;

-- Allocation-only протокол обычного Forward. Payload не удостоверяет право:
-- actual INSERT остаётся SECURITY INVOKER и проходит прежний authority/fold graph.
-- Постоянный anchor закрывает DISCARD TEMP/удаление private storage до COMMIT.
CREATE TABLE kaname.authority_forward_emit_anchor_v4(
 backend integer NOT NULL,transaction_id xid8 NOT NULL,nonce uuid NOT NULL,
 invoker_oid oid NOT NULL,program_oid oid NOT NULL,effects_oid oid NOT NULL,receipts_oid oid NOT NULL,
 effect_count integer NOT NULL CHECK(effect_count>=0),finished boolean NOT NULL,batch jsonb NOT NULL,batch_required boolean NOT NULL,
 write_batch jsonb NOT NULL,write_required boolean NOT NULL,
 PRIMARY KEY(backend,transaction_id,nonce));
REVOKE ALL ON kaname.authority_forward_emit_anchor_v4 FROM PUBLIC;
DO $$ DECLARE r record;BEGIN
 FOR r IN SELECT DISTINCT u.rolname FROM pg_catalog.pg_class c
 CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_catalog.pg_roles u ON u.oid=a.grantee
 WHERE c.oid='kaname.authority_forward_emit_anchor_v4'::regclass AND a.grantee<>c.relowner LOOP
  EXECUTE format('REVOKE ALL ON kaname.authority_forward_emit_anchor_v4 FROM %I',r.rolname);
 END LOOP;
END $$;

CREATE FUNCTION kaname._authority_forward_context_v4() RETURNS oid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE invoker oid;
BEGIN
 -- Невалидная подпись/strict/compare отвергается прежней свежей аттестацией.
 -- Валидная signed подпись тоже не превращается в unsigned allocation.
 IF kaname.authority_protocol_attestation() IS NOT NULL THEN
  RAISE EXCEPTION 'forward allocation requires unsigned compatibility' USING ERRCODE='42501';END IF;
 SELECT oid INTO STRICT invoker FROM pg_catalog.pg_roles
 WHERE rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
 IF NOT has_table_privilege(invoker,'kaname.fga_outbox'::regclass,'INSERT')
 OR NOT has_sequence_privilege(invoker,'kaname.fga_outbox_id_seq'::regclass,'USAGE,UPDATE') THEN
  RAISE EXCEPTION 'forward allocation lacks original privileges' USING ERRCODE='42501';END IF;
 RETURN invoker;
END $$;

CREATE FUNCTION kaname._authority_forward_custody_v4() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE owner_oid oid;
BEGIN
 SELECT oid INTO STRICT owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
 -- Каждый вызов заново проверяет три OID; LEFT JOIN сохраняет отказ при отсутствии storage.
 IF EXISTS(SELECT 1 FROM (VALUES
  (to_regclass('pg_temp.kaname_forward_program_v4')),
  (to_regclass('pg_temp.kaname_forward_effects_v4')),
  (to_regclass('pg_temp.kaname_forward_receipts_v4'))
 ) expected(relation_id) LEFT JOIN pg_catalog.pg_class c ON c.oid=expected.relation_id
 WHERE expected.relation_id IS NULL OR c.oid IS NULL
  OR NOT (c.relowner=owner_oid AND c.relkind='r' AND c.relpersistence='t'
   AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND NOT c.relhasrules AND NOT c.relhassubclass)
  OR (SELECT t.oid FROM pg_catalog.pg_trigger t WHERE t.tgrelid=expected.relation_id LIMIT 1) IS NOT NULL
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid=expected.relation_id OR inhparent=expected.relation_id)
  OR EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
   WHERE a.grantee<>owner_oid)
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) x
   WHERE a.attrelid=expected.relation_id AND a.attacl IS NOT NULL AND x.grantee<>owner_oid)) THEN
  RAISE EXCEPTION 'untrusted forward allocation storage' USING ERRCODE='42501';END IF;
END $$;

CREATE FUNCTION kaname._authority_forward_shape_v4() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE expected record;relation_id oid;
BEGIN
 PERFORM kaname._authority_forward_custody_v4();
 FOR expected IN SELECT * FROM (VALUES
  ('kaname_forward_program_v4',ARRAY['nonce','backend','transaction_id','invoker_oid','effects_oid','receipts_oid','effect_count','phase'],
   ARRAY['uuid','integer','xid8','oid','oid','oid','integer','text'],1),
  ('kaname_forward_effects_v4',ARRAY['nonce','ordinal','reserved_id','row_value','row_digest'],
   ARRAY['uuid','integer','bigint','jsonb','bytea'],2),
  ('kaname_forward_receipts_v4',ARRAY['nonce','ordinal','reserved_id','backend','transaction_id','invoker_oid','program_oid','effects_oid',
   'table_oid','key_namespace','key_hash','objsubid','lock_mode','claimed','guarded','consumed'],
   ARRAY['uuid','integer','bigint','integer','xid8','oid','oid','oid','oid','integer','integer','integer','text','boolean','boolean','boolean'],2)
 ) x(table_name,column_names,type_names,index_count) LOOP
  relation_id:=to_regclass('pg_temp.'||expected.table_name);
  IF (SELECT array_agg(a.attname::text ORDER BY a.attnum) FROM pg_catalog.pg_attribute a
   WHERE a.attrelid=relation_id AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM expected.column_names
  OR (SELECT array_agg(a.atttypid ORDER BY a.attnum) FROM pg_catalog.pg_attribute a
   WHERE a.attrelid=relation_id AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM
   (SELECT array_agg(v::regtype::oid ORDER BY n) FROM unnest(expected.type_names) WITH ORDINALITY t(v,n))
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=relation_id AND a.attnum>0
   AND (a.attisdropped OR NOT a.attnotnull OR a.attgenerated<>'' OR a.attidentity<>'' OR a.atthasdef))
  OR (SELECT count(*) FROM pg_catalog.pg_index WHERE indrelid=relation_id)<>expected.index_count
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
   JOIN pg_catalog.pg_am m ON m.oid=c.relam WHERE i.indrelid=relation_id AND
   (NOT i.indisunique OR NOT i.indisvalid OR NOT i.indisready OR NOT i.indislive
    OR i.indexprs IS NOT NULL OR i.indpred IS NOT NULL OR m.amname<>'btree' OR i.indnatts<>i.indnkeyatts
    OR NOT (CASE WHEN expected.table_name='kaname_forward_program_v4' THEN i.indisprimary AND i.indkey='1'::int2vector
     ELSE (i.indisprimary AND i.indkey='1 2'::int2vector) OR (NOT i.indisprimary AND i.indkey='3'::int2vector) END)))
  THEN RAISE EXCEPTION 'forward allocation storage shape changed' USING ERRCODE='42501';END IF;
 END LOOP;
END $$;

CREATE FUNCTION kaname._authority_forward_program_v4(p_nonce uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program record;anchor kaname.authority_forward_emit_anchor_v4%ROWTYPE;invoker oid;
BEGIN
 PERFORM kaname._authority_forward_custody_v4();
 SELECT oid INTO STRICT invoker FROM pg_catalog.pg_roles
 WHERE rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
 SELECT a.* INTO anchor FROM kaname.authority_forward_emit_anchor_v4 a
 WHERE a.backend=pg_backend_pid() AND a.transaction_id=pg_current_xact_id() AND a.nonce=p_nonce;
 IF NOT FOUND THEN RAISE EXCEPTION 'forward allocation anchor missing or foreign' USING ERRCODE='42501';END IF;
 SELECT p.* INTO program FROM pg_temp.kaname_forward_program_v4 p WHERE p.nonce=p_nonce;
 IF NOT FOUND THEN RAISE EXCEPTION 'forward allocation program missing' USING ERRCODE='42501';END IF;
 IF program.backend IS DISTINCT FROM anchor.backend OR program.transaction_id IS DISTINCT FROM anchor.transaction_id
 OR program.invoker_oid IS DISTINCT FROM invoker OR program.invoker_oid IS DISTINCT FROM anchor.invoker_oid
 OR anchor.program_oid IS DISTINCT FROM to_regclass('pg_temp.kaname_forward_program_v4')
 OR anchor.effects_oid IS DISTINCT FROM to_regclass('pg_temp.kaname_forward_effects_v4')
 OR anchor.receipts_oid IS DISTINCT FROM to_regclass('pg_temp.kaname_forward_receipts_v4')
 OR program.effects_oid IS DISTINCT FROM anchor.effects_oid OR program.receipts_oid IS DISTINCT FROM anchor.receipts_oid
 OR program.effect_count IS DISTINCT FROM anchor.effect_count OR program.effect_count<0
 OR program.phase NOT IN ('prepared','claimed','finished')
 OR (program.phase='finished') IS DISTINCT FROM anchor.finished THEN
  RAISE EXCEPTION 'forward allocation program scope changed' USING ERRCODE='42501';END IF;
 RETURN to_jsonb(program)||jsonb_build_object('program_oid',anchor.program_oid);
END $$;

CREATE FUNCTION kaname.authority_forward_prepare_v4(p_payloads jsonb[]) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE invoker oid;owner_oid oid;command_nonce uuid;item record;relation_id oid;grantee record;
 identifiers bigint[];present boolean;effect_count integer;
BEGIN
 invoker:=kaname._authority_forward_context_v4();
 IF p_payloads IS NULL OR coalesce(array_ndims(p_payloads),1)<>1
 OR EXISTS(SELECT 1 FROM unnest(p_payloads) p WHERE jsonb_typeof(p) IS DISTINCT FROM 'object') THEN
  RAISE EXCEPTION 'invalid forward allocation payload array' USING ERRCODE='42501';END IF;
 effect_count:=cardinality(p_payloads);
 IF pg_get_serial_sequence('kaname.fga_outbox','id')::regclass IS DISTINCT FROM 'kaname.fga_outbox_id_seq'::regclass
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid='kaname.fga_outbox'::regclass OR inhparent='kaname.fga_outbox'::regclass) THEN
  RAISE EXCEPTION 'forward allocation requires exact owned sequence relation' USING ERRCODE='42501';END IF;
 SELECT oid INTO STRICT owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
 IF to_regclass('pg_temp.kaname_forward_program_v4') IS NULL
  AND to_regclass('pg_temp.kaname_forward_effects_v4') IS NULL
  AND to_regclass('pg_temp.kaname_forward_receipts_v4') IS NULL THEN
  CREATE TEMP TABLE pg_temp.kaname_forward_program_v4(
   nonce uuid PRIMARY KEY,backend integer NOT NULL,transaction_id xid8 NOT NULL,invoker_oid oid NOT NULL,
   effects_oid oid NOT NULL,receipts_oid oid NOT NULL,effect_count integer NOT NULL,phase text NOT NULL) ON COMMIT DELETE ROWS;
  CREATE TEMP TABLE pg_temp.kaname_forward_effects_v4(
   nonce uuid NOT NULL,ordinal integer NOT NULL,reserved_id bigint NOT NULL UNIQUE,
   row_value jsonb NOT NULL,row_digest bytea NOT NULL,PRIMARY KEY(nonce,ordinal)) ON COMMIT DELETE ROWS;
  CREATE TEMP TABLE pg_temp.kaname_forward_receipts_v4(
   nonce uuid NOT NULL,ordinal integer NOT NULL,reserved_id bigint NOT NULL UNIQUE,
   backend integer NOT NULL,transaction_id xid8 NOT NULL,invoker_oid oid NOT NULL,program_oid oid NOT NULL,effects_oid oid NOT NULL,
   table_oid oid NOT NULL,key_namespace integer NOT NULL,key_hash integer NOT NULL,objsubid integer NOT NULL,lock_mode text NOT NULL,
   claimed boolean NOT NULL,guarded boolean NOT NULL,consumed boolean NOT NULL,PRIMARY KEY(nonce,ordinal)) ON COMMIT DELETE ROWS;
  FOREACH relation_id IN ARRAY ARRAY['pg_temp.kaname_forward_program_v4'::regclass,
   'pg_temp.kaname_forward_effects_v4'::regclass,'pg_temp.kaname_forward_receipts_v4'::regclass] LOOP
   EXECUTE format('REVOKE ALL ON %s FROM PUBLIC',relation_id::regclass);
   FOR grantee IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_class c
    CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
    WHERE c.oid=relation_id AND a.grantee<>owner_oid LOOP
    EXECUTE format('REVOKE ALL ON %s FROM %I',relation_id::regclass,grantee.rolname);
   END LOOP;
  END LOOP;
 END IF;
 PERFORM kaname._authority_forward_shape_v4();
 -- RX actual таблицы предшествует каждому key; никаких новых account/binding
 -- или общих advisory замков. Порядок тот же, что signed sequence reserve.
 LOCK TABLE ONLY kaname.fga_outbox IN ROW EXCLUSIVE MODE;
 command_nonce:=gen_random_uuid();
 INSERT INTO pg_temp.kaname_forward_program_v4 VALUES(command_nonce,pg_backend_pid(),pg_current_xact_id(),invoker,
  'pg_temp.kaname_forward_effects_v4'::regclass,'pg_temp.kaname_forward_receipts_v4'::regclass,effect_count,'prepared');
 INSERT INTO pg_temp.kaname_forward_effects_v4(nonce,ordinal,reserved_id,row_value,row_digest)
 SELECT command_nonce,n::integer,nextval('kaname.fga_outbox_id_seq'::regclass),row_value,sha256(convert_to(row_value::text,'UTF8'))
 FROM (SELECT p,n,jsonb_build_object('event_type','fga.tuple.write','payload',p,'created_at',transaction_timestamp()) row_value
  FROM unnest(p_payloads) WITH ORDINALITY t(p,n)) q ORDER BY n;
 IF EXISTS(SELECT 1 FROM pg_temp.kaname_forward_effects_v4 WHERE nonce=command_nonce AND reserved_id<=0) THEN
  RAISE EXCEPTION 'sequence identity exhausted' USING ERRCODE='P1034';END IF;
 FOR item IN SELECT DISTINCT hashtext(e.reserved_id::text) key_hash
  FROM pg_temp.kaname_forward_effects_v4 e WHERE e.nonce=command_nonce ORDER BY key_hash LOOP
  PERFORM pg_advisory_xact_lock(1262569305,item.key_hash);
 END LOOP;
 FOR identifiers IN SELECT array_agg(id ORDER BY id) FROM (
  SELECT reserved_id id,(row_number() OVER (ORDER BY reserved_id)-1)/256 page
  FROM pg_temp.kaname_forward_effects_v4 WHERE nonce=command_nonce) q GROUP BY page ORDER BY page LOOP
  SELECT EXISTS(SELECT 1 FROM (SELECT id FROM ONLY kaname.fga_outbox WHERE id=ANY(identifiers) ORDER BY id FOR UPDATE) locked) INTO present;
  IF present THEN RAISE EXCEPTION 'sequence reservation collided' USING ERRCODE='P1034';END IF;
 END LOOP;
 -- Публикация receipt только ПОСЛЕ actual успешного acquisition всех ключей.
 -- Transactional DML и xact locks откатываются одним savepoint/subtransaction.
 INSERT INTO pg_temp.kaname_forward_receipts_v4
 SELECT e.nonce,e.ordinal,e.reserved_id,pg_backend_pid(),pg_current_xact_id(),invoker,
  'pg_temp.kaname_forward_program_v4'::regclass,'pg_temp.kaname_forward_effects_v4'::regclass,
  'kaname.fga_outbox'::regclass,1262569305,hashtext(e.reserved_id::text),2,'ExclusiveLock',false,false,false
 FROM pg_temp.kaname_forward_effects_v4 e WHERE e.nonce=command_nonce;
 INSERT INTO kaname.authority_forward_emit_anchor_v4 VALUES(pg_backend_pid(),pg_current_xact_id(),command_nonce,invoker,
  'pg_temp.kaname_forward_program_v4'::regclass,'pg_temp.kaname_forward_effects_v4'::regclass,
  'pg_temp.kaname_forward_receipts_v4'::regclass,effect_count,false,'{}'::jsonb,false,'{}'::jsonb,false);
 RETURN command_nonce;
END $$;

CREATE FUNCTION kaname.authority_forward_claim_v4(p_nonce uuid)
RETURNS TABLE(id bigint,event_type text,payload jsonb,created_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;changed integer;
BEGIN
 PERFORM kaname._authority_forward_context_v4();
 program:=kaname._authority_forward_program_v4(p_nonce);
 IF program->>'phase'<>'prepared' THEN RAISE EXCEPTION 'forward allocation claim replay' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_forward_receipts_v4 r SET claimed=true
 WHERE r.nonce=p_nonce AND NOT r.claimed AND NOT r.guarded AND NOT r.consumed;
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed<>(program->>'effect_count')::integer
 OR (SELECT count(*) FROM pg_temp.kaname_forward_effects_v4 e WHERE e.nonce=p_nonce)<>changed THEN
  RAISE EXCEPTION 'forward allocation exact claim changed' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_forward_program_v4 SET phase='claimed' WHERE nonce=p_nonce AND phase='prepared';
 RETURN QUERY SELECT e.reserved_id,e.row_value->>'event_type',e.row_value->'payload',(e.row_value->>'created_at')::timestamptz
 FROM pg_temp.kaname_forward_effects_v4 e WHERE e.nonce=p_nonce ORDER BY e.ordinal;
END $$;

CREATE FUNCTION kaname._authority_forward_row_v4(p_id bigint,p_row jsonb,p_applied boolean) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE effect record;receipt record;effect_found boolean;receipt_found boolean;program jsonb;changed integer;
BEGIN
 -- Этот helper private; оба actual trigger caller уже получили свежий NULL
 -- proof. Нет active anchor — прежний произвольный SQL идёт в прежний guard.
 IF NOT EXISTS(SELECT 1 FROM kaname.authority_forward_emit_anchor_v4 a
  WHERE a.backend=pg_backend_pid() AND a.transaction_id=pg_current_xact_id_if_assigned()) THEN RETURN false;END IF;
 PERFORM kaname._authority_forward_custody_v4();
 SELECT e.* INTO effect FROM pg_temp.kaname_forward_effects_v4 e WHERE e.reserved_id=p_id;effect_found:=FOUND;
 SELECT r.* INTO receipt FROM pg_temp.kaname_forward_receipts_v4 r WHERE r.reserved_id=p_id;receipt_found:=FOUND;
 -- Непокрытый explicit ID сохраняет свежую старую проверку. Удаление обеих
 -- строк owner fault не закрывает anchor: finish/COMMIT сверяют полный count.
 IF NOT effect_found AND NOT receipt_found THEN RETURN false;END IF;
 IF NOT effect_found OR NOT receipt_found THEN
  RAISE EXCEPTION 'forward allocation exact receipt missing' USING ERRCODE='42501';END IF;
 program:=kaname._authority_forward_program_v4(effect.nonce);
 IF program->>'phase' IS DISTINCT FROM 'claimed' OR receipt.nonce IS DISTINCT FROM effect.nonce
 OR receipt.ordinal IS DISTINCT FROM effect.ordinal OR effect.ordinal<1 OR effect.ordinal>(program->>'effect_count')::integer
 OR receipt.backend IS DISTINCT FROM pg_backend_pid() OR receipt.transaction_id IS DISTINCT FROM pg_current_xact_id()
 OR receipt.invoker_oid IS DISTINCT FROM (program->>'invoker_oid')::oid
 OR receipt.program_oid IS DISTINCT FROM (program->>'program_oid')::oid
 OR receipt.effects_oid IS DISTINCT FROM (program->>'effects_oid')::oid
 OR receipt.table_oid IS DISTINCT FROM 'kaname.fga_outbox'::regclass::oid
 OR receipt.key_namespace IS DISTINCT FROM 1262569305 OR receipt.key_hash IS DISTINCT FROM hashtext(p_id::text)
 OR receipt.objsubid IS DISTINCT FROM 2 OR receipt.lock_mode IS DISTINCT FROM 'ExclusiveLock'
 OR NOT receipt.claimed OR receipt.consumed OR receipt.guarded IS DISTINCT FROM p_applied
 OR effect.row_digest IS DISTINCT FROM sha256(convert_to(p_row::text,'UTF8')) OR effect.row_value IS DISTINCT FROM p_row THEN
  RAISE EXCEPTION 'forward allocation receipt scope or exact row changed' USING ERRCODE='42501';END IF;
 IF p_applied THEN
  UPDATE pg_temp.kaname_forward_receipts_v4 SET consumed=true
  WHERE nonce=effect.nonce AND ordinal=effect.ordinal AND claimed AND guarded AND NOT consumed;
 ELSE
  UPDATE pg_temp.kaname_forward_receipts_v4 SET guarded=true
  WHERE nonce=effect.nonce AND ordinal=effect.ordinal AND claimed AND NOT guarded AND NOT consumed;
 END IF;
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed<>1 THEN RAISE EXCEPTION 'forward allocation receipt replay' USING ERRCODE='42501';END IF;
 RETURN true;
END $$;

CREATE FUNCTION kaname._authority_forward_complete_v4(p_nonce uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;expected integer;
BEGIN
 PERFORM kaname._authority_forward_shape_v4();
 program:=kaname._authority_forward_program_v4(p_nonce);expected:=(program->>'effect_count')::integer;
 IF EXISTS(SELECT 1 FROM kaname.authority_forward_emit_anchor_v4 WHERE backend=pg_backend_pid()
  AND transaction_id=pg_current_xact_id() AND nonce=p_nonce AND batch_required
  AND batch->>'phase' IS DISTINCT FROM 'finished') THEN
  RAISE EXCEPTION 'native batch completion obligation unfinished' USING ERRCODE='42501';END IF;
 PERFORM kaname.authority_native_delete_batch_read_v4();
 IF EXISTS(SELECT 1 FROM kaname.authority_forward_emit_anchor_v4 WHERE backend=pg_backend_pid()
  AND transaction_id=pg_current_xact_id() AND nonce=p_nonce AND write_required
  AND write_batch->>'phase' IS DISTINCT FROM 'finished') THEN
  RAISE EXCEPTION 'native write completion obligation unfinished' USING ERRCODE='42501';END IF;
 PERFORM kaname.authority_native_write_read_v4();

 IF program->>'phase' IS DISTINCT FROM 'finished'
 OR (SELECT count(*) FROM pg_temp.kaname_forward_effects_v4 WHERE nonce=p_nonce)<>expected
 OR (SELECT count(*) FROM pg_temp.kaname_forward_receipts_v4 WHERE nonce=p_nonce)<>expected
 OR EXISTS(SELECT 1 FROM pg_temp.kaname_forward_effects_v4 e
  LEFT JOIN pg_temp.kaname_forward_receipts_v4 r ON r.nonce=e.nonce AND r.ordinal=e.ordinal
  WHERE e.nonce=p_nonce AND (r.reserved_id IS DISTINCT FROM e.reserved_id
   OR e.ordinal<1 OR e.ordinal>expected OR e.reserved_id<=0
   OR e.row_digest IS DISTINCT FROM sha256(convert_to(e.row_value::text,'UTF8'))
   OR r.backend IS DISTINCT FROM pg_backend_pid() OR r.transaction_id IS DISTINCT FROM pg_current_xact_id()
   OR r.invoker_oid IS DISTINCT FROM (program->>'invoker_oid')::oid
   OR r.program_oid IS DISTINCT FROM (program->>'program_oid')::oid OR r.effects_oid IS DISTINCT FROM (program->>'effects_oid')::oid
   OR r.table_oid IS DISTINCT FROM 'kaname.fga_outbox'::regclass::oid OR r.key_namespace IS DISTINCT FROM 1262569305
   OR r.key_hash IS DISTINCT FROM hashtext(e.reserved_id::text) OR r.objsubid IS DISTINCT FROM 2
   OR r.lock_mode IS DISTINCT FROM 'ExclusiveLock' OR r.claimed IS DISTINCT FROM true
   OR r.guarded IS DISTINCT FROM true OR r.consumed IS DISTINCT FROM true)) THEN
  RAISE EXCEPTION 'forward allocation program incomplete or changed' USING ERRCODE='42501';END IF;
END $$;

CREATE FUNCTION kaname.authority_forward_finish_v4(p_nonce uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;changed integer;
BEGIN
 PERFORM kaname._authority_forward_context_v4();
 program:=kaname._authority_forward_program_v4(p_nonce);
 IF program->>'phase' IS DISTINCT FROM 'claimed' THEN
  RAISE EXCEPTION 'forward allocation finish replay' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_forward_program_v4 SET phase='finished' WHERE nonce=p_nonce AND phase='claimed';
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed<>1 THEN RAISE EXCEPTION 'forward allocation finish replay' USING ERRCODE='42501';END IF;
 UPDATE kaname.authority_forward_emit_anchor_v4 SET finished=true
 WHERE backend=pg_backend_pid() AND transaction_id=pg_current_xact_id() AND nonce=p_nonce AND NOT finished;
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed<>1 THEN RAISE EXCEPTION 'forward allocation completion anchor missing' USING ERRCODE='42501';END IF;
 PERFORM kaname._authority_forward_complete_v4(p_nonce);
END $$;

CREATE FUNCTION kaname.authority_forward_emit_v4(p_payloads jsonb[]) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE command_nonce uuid;
BEGIN
 IF p_payloads IS NOT NULL AND cardinality(p_payloads)=0 THEN RETURN;END IF;
 command_nonce:=kaname.authority_forward_prepare_v4(p_payloads);
 IF has_function_privilege(current_user,'kaname.authority_native_write_arm_v4(uuid)','EXECUTE') THEN
  PERFORM kaname.authority_native_write_arm_v4(command_nonce);
 END IF;
 INSERT INTO kaname.fga_outbox(id,event_type,payload,created_at)
 SELECT id,event_type,payload,created_at FROM kaname.authority_forward_claim_v4(command_nonce);
 -- AFTER STATEMENT fold и остальные original triggers уже завершились.
 PERFORM kaname.authority_forward_finish_v4(command_nonce);
END $$;

-- Отдельная дверь unsigned DELETE: резерв сохраняет прежние RX/key receipts,
-- а окончательная метка возникает при вычислении строки actual INSERT.
CREATE FUNCTION kaname.authority_native_delete_prepare_v4(p_payloads jsonb[]) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE command_nonce uuid;program jsonb;changed integer;expected integer;
BEGIN
 PERFORM kaname._authority_forward_context_v4();
 IF p_payloads IS NULL OR coalesce(array_ndims(p_payloads),1)<>1
 OR EXISTS(SELECT 1 FROM unnest(p_payloads) p WHERE jsonb_typeof(p) IS DISTINCT FROM 'object'
  OR nullif(p->'source_version','null'::jsonb) IS NOT NULL) THEN
  RAISE EXCEPTION 'native delete requires unversioned payload objects' USING ERRCODE='42501';END IF;
 -- Отказ owner-ordered payload происходит до nextval и любого резерва.
 -- Только созданный этим вызовом nonce переводится из WRITE в DELETE.
 command_nonce:=kaname.authority_forward_prepare_v4(p_payloads);
 program:=kaname._authority_forward_program_v4(command_nonce);expected:=cardinality(p_payloads);
 IF program->>'phase' IS DISTINCT FROM 'prepared' OR (program->>'effect_count')::integer<>expected
 OR (SELECT count(*) FROM pg_temp.kaname_forward_effects_v4 WHERE nonce=command_nonce)<>expected
 OR (SELECT count(*) FROM pg_temp.kaname_forward_receipts_v4 WHERE nonce=command_nonce)<>expected
 OR EXISTS(SELECT 1 FROM pg_temp.kaname_forward_receipts_v4
  WHERE nonce=command_nonce AND (claimed OR guarded OR consumed)) THEN
  RAISE EXCEPTION 'native delete preparation scope changed' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_forward_effects_v4 e
 SET row_value=jsonb_build_object('event_type','fga.tuple.delete','payload',q.p,'created_at',NULL),
  row_digest=sha256(convert_to(jsonb_build_object('event_type','fga.tuple.delete','payload',q.p,'created_at',NULL)::text,'UTF8'))
 FROM unnest(p_payloads) WITH ORDINALITY q(p,n)
 WHERE e.nonce=command_nonce AND e.ordinal=q.n
  AND e.row_value=jsonb_build_object('event_type','fga.tuple.write','payload',q.p,'created_at',transaction_timestamp())
  AND e.row_digest=sha256(convert_to(e.row_value::text,'UTF8'));
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed<>expected THEN RAISE EXCEPTION 'native delete exact preparation changed' USING ERRCODE='42501';END IF;
 RETURN command_nonce;
END $$;

CREATE FUNCTION kaname.authority_native_delete_stamp_v4(p_nonce uuid,p_id bigint,p_payload jsonb) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;effect record;receipt record;expected jsonb;actual jsonb;at_time timestamptz;changed integer;
BEGIN
 PERFORM kaname._authority_forward_context_v4();
 program:=kaname._authority_forward_program_v4(p_nonce);
 IF program->>'phase' IS DISTINCT FROM 'claimed' OR p_id IS NULL OR p_id<=0
 OR jsonb_typeof(p_payload) IS DISTINCT FROM 'object'
 OR nullif(p_payload->'source_version','null'::jsonb) IS NOT NULL THEN
  RAISE EXCEPTION 'native delete stamp requires claimed unversioned effect' USING ERRCODE='42501';END IF;
 SELECT e.* INTO effect FROM pg_temp.kaname_forward_effects_v4 e WHERE e.nonce=p_nonce AND e.reserved_id=p_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'native delete stamp effect missing or foreign' USING ERRCODE='42501';END IF;
 SELECT r.* INTO receipt FROM pg_temp.kaname_forward_receipts_v4 r WHERE r.nonce=p_nonce AND r.reserved_id=p_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'native delete stamp receipt missing or foreign' USING ERRCODE='42501';END IF;
 expected:=jsonb_build_object('event_type','fga.tuple.delete','payload',p_payload,'created_at',NULL);
 IF receipt.ordinal IS DISTINCT FROM effect.ordinal OR effect.ordinal<1 OR effect.ordinal>(program->>'effect_count')::integer
 OR receipt.backend IS DISTINCT FROM pg_backend_pid() OR receipt.transaction_id IS DISTINCT FROM pg_current_xact_id()
 OR receipt.invoker_oid IS DISTINCT FROM (program->>'invoker_oid')::oid
 OR receipt.program_oid IS DISTINCT FROM (program->>'program_oid')::oid
 OR receipt.effects_oid IS DISTINCT FROM (program->>'effects_oid')::oid
 OR receipt.table_oid IS DISTINCT FROM 'kaname.fga_outbox'::regclass::oid
 OR receipt.key_namespace IS DISTINCT FROM 1262569305 OR receipt.key_hash IS DISTINCT FROM hashtext(p_id::text)
 OR receipt.objsubid IS DISTINCT FROM 2 OR receipt.lock_mode IS DISTINCT FROM 'ExclusiveLock'
 OR receipt.claimed IS DISTINCT FROM true OR receipt.guarded IS DISTINCT FROM false OR receipt.consumed IS DISTINCT FROM false
 OR effect.row_value IS DISTINCT FROM expected OR effect.row_digest IS DISTINCT FROM sha256(convert_to(expected::text,'UTF8')) THEN
  RAISE EXCEPTION 'native delete stamp scope, payload or unbound clock changed' USING ERRCODE='42501';END IF;
 -- VOLATILE вызывается в targetlist INSERT после materialized claim и всех
 -- reserve waits. Часы не принимаются от клиента и не вычисляются в SRF.
 at_time:=clock_timestamp();actual:=jsonb_set(expected,'{created_at}',to_jsonb(at_time));
 UPDATE pg_temp.kaname_forward_effects_v4 SET row_value=actual,row_digest=sha256(convert_to(actual::text,'UTF8'))
 WHERE nonce=p_nonce AND ordinal=effect.ordinal AND reserved_id=p_id AND row_value=expected
  AND row_digest=sha256(convert_to(expected::text,'UTF8'));
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed<>1 THEN RAISE EXCEPTION 'native delete stamp replay' USING ERRCODE='42501';END IF;
 RETURN at_time;
END $$;

CREATE FUNCTION kaname.authority_native_delete_emit_v4(p_payloads jsonb[]) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE command_nonce uuid;
BEGIN
 IF p_payloads IS NOT NULL AND cardinality(p_payloads)=0 THEN RETURN;END IF;
 command_nonce:=kaname.authority_native_delete_prepare_v4(p_payloads);
 INSERT INTO kaname.fga_outbox(id,event_type,payload,created_at)
 SELECT id,event_type,payload,kaname.authority_native_delete_stamp_v4(command_nonce,id,payload)
 FROM kaname.authority_forward_claim_v4(command_nonce);
 -- Finish выполняется только после всех прежних AFTER STATEMENT guards/fold.
 PERFORM kaname.authority_forward_finish_v4(command_nonce);
END $$;

CREATE FUNCTION kaname._authority_forward_anchor_complete_v4() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME<>'authority_forward_emit_anchor_v4'
 OR TG_OP<>'INSERT' OR TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW'
 OR TG_RELID IS DISTINCT FROM 'kaname.authority_forward_emit_anchor_v4'::regclass
 OR NEW.backend IS DISTINCT FROM pg_backend_pid() OR NEW.transaction_id IS DISTINCT FROM pg_current_xact_id() THEN
  RAISE EXCEPTION 'forward allocation completion trigger scope changed' USING ERRCODE='42501';END IF;
 PERFORM kaname._authority_forward_context_v4();
 PERFORM kaname._authority_forward_complete_v4(NEW.nonce);
 DELETE FROM kaname.authority_forward_emit_anchor_v4
 WHERE backend=NEW.backend AND transaction_id=NEW.transaction_id AND nonce=NEW.nonce AND finished;
 IF NOT FOUND THEN RAISE EXCEPTION 'forward allocation completion anchor lost' USING ERRCODE='42501';END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER authority_forward_anchor_complete_v4
 AFTER INSERT ON kaname.authority_forward_emit_anchor_v4 DEFERRABLE INITIALLY DEFERRED
 FOR EACH ROW EXECUTE FUNCTION kaname._authority_forward_anchor_complete_v4();

CREATE FUNCTION kaname._authority_forward_storage_v4() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE owner_oid oid;anchor oid:=to_regclass('kaname.authority_forward_emit_anchor_v4');
BEGIN
 SELECT relowner INTO owner_oid FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass;
 IF anchor IS NULL OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=anchor
  AND c.relowner=owner_oid AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity
  AND NOT c.relforcerowsecurity AND NOT c.relhasrules AND NOT c.relhassubclass)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid=anchor OR inhparent=anchor)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
  WHERE c.oid=anchor AND a.grantee<>owner_oid)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) x
  WHERE a.attrelid=anchor AND x.grantee<>owner_oid)
 OR (SELECT array_agg(a.attname::text ORDER BY a.attnum) FROM pg_catalog.pg_attribute a
  WHERE a.attrelid=anchor AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM
  ARRAY['backend','transaction_id','nonce','invoker_oid','program_oid','effects_oid','receipts_oid','effect_count','finished','batch','batch_required','write_batch','write_required']
 OR (SELECT array_agg(a.atttypid ORDER BY a.attnum) FROM pg_catalog.pg_attribute a
  WHERE a.attrelid=anchor AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM
  ARRAY['integer'::regtype::oid,'xid8'::regtype::oid,'uuid'::regtype::oid,'oid'::regtype::oid,'oid'::regtype::oid,
   'oid'::regtype::oid,'oid'::regtype::oid,'integer'::regtype::oid,'boolean'::regtype::oid,'jsonb'::regtype::oid,'boolean'::regtype::oid,'jsonb'::regtype::oid,'boolean'::regtype::oid]
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid=anchor AND attnum>0
  AND (attisdropped OR NOT attnotnull OR attgenerated<>'' OR attidentity<>'' OR atthasdef))
 OR (SELECT count(*) FROM pg_catalog.pg_index WHERE indrelid=anchor)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
  JOIN pg_catalog.pg_am m ON m.oid=c.relam WHERE i.indrelid=anchor AND i.indisprimary AND i.indisunique
  AND i.indisvalid AND i.indisready AND i.indislive AND i.indkey='1 2 3'::int2vector
  AND i.indexprs IS NULL AND i.indpred IS NULL AND i.indnatts=i.indnkeyatts AND m.amname='btree')
 OR (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgrelid=anchor)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=anchor AND tgname='authority_forward_anchor_complete_v4'
  AND tgfoid='kaname._authority_forward_anchor_complete_v4()'::regprocedure AND tgtype::integer=5
  AND tgenabled='O' AND NOT tgisinternal AND tgconstraint<>0 AND tgdeferrable AND tginitdeferred
  AND tgnargs=0 AND tgargs=''::bytea AND tgattr=''::int2vector AND tgqual IS NULL AND tgoldtable IS NULL AND tgnewtable IS NULL)
 OR (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname._authority_forward_anchor_complete_v4()'::regprocedure)<>1
 THEN RETURN false;END IF;
 IF (SELECT count(*) FROM pg_catalog.pg_constraint WHERE conrelid=anchor)<>3
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid=anchor AND contype='p'
  AND conkey=ARRAY[1,2,3]::smallint[] AND convalidated AND NOT condeferrable AND NOT condeferred)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid=anchor AND contype='c'
  AND conkey=ARRAY[8]::smallint[] AND convalidated AND NOT condeferrable AND NOT condeferred
  AND pg_get_expr(conbin,conrelid)='(effect_count >= 0)')
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_trigger t ON t.tgconstraint=c.oid
  WHERE c.conrelid=anchor AND c.contype='t' AND c.conname='authority_forward_anchor_complete_v4'
   AND c.convalidated AND c.condeferrable AND c.condeferred AND c.conkey IS NULL AND c.confkey IS NULL
   AND c.confrelid=0 AND c.contypid=0 AND c.conbin IS NULL
   AND t.tgrelid=anchor AND t.tgname='authority_forward_anchor_complete_v4'
   AND t.tgconstrrelid=0 AND t.tgconstrindid=0) THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM (VALUES
  ('_authority_native_write_weights_v4(jsonb)','jsonb',1,false,ARRAY['p_rows']),
  ('_authority_native_write_closure_v4()','boolean',0,false,NULL::text[]),
  ('authority_native_write_arm_v4(uuid)','void',1,false,ARRAY['p_nonce']),
  ('authority_native_write_read_v4()','jsonb',0,false,NULL::text[]),
  ('_authority_native_delete_batch_graph_v4()','boolean',0,false,NULL::text[]),
  ('authority_native_delete_batch_read_v4()','jsonb',0,false,NULL::text[]),
  ('_authority_native_delete_batch_begin_v4()','trigger',0,false,NULL::text[]),
  ('_authority_native_delete_batch_end_v4()','trigger',0,false,NULL::text[]),
  ('authority_forward_emit_v4(jsonb[])','void',1,false,ARRAY['p_payloads']),
  ('authority_forward_prepare_v4(jsonb[])','uuid',1,false,ARRAY['p_payloads']),
  ('authority_forward_claim_v4(uuid)','record',1,true,ARRAY['p_nonce','id','event_type','payload','created_at']),
  ('authority_forward_finish_v4(uuid)','void',1,false,ARRAY['p_nonce']),
  ('_authority_forward_custody_v4()','void',0,false,NULL::text[]),
  ('_authority_forward_shape_v4()','void',0,false,NULL::text[]),
  ('_authority_forward_context_v4()','oid',0,false,NULL::text[]),
  ('_authority_forward_program_v4(uuid)','jsonb',1,false,ARRAY['p_nonce']),
  ('_authority_forward_row_v4(bigint,jsonb,boolean)','boolean',3,false,ARRAY['p_id','p_row','p_applied']),
  ('_authority_forward_complete_v4(uuid)','void',1,false,ARRAY['p_nonce']),
  ('_authority_forward_anchor_complete_v4()','trigger',0,false,NULL::text[]),
  ('_authority_forward_storage_v4()','boolean',0,false,NULL::text[])
 ) e(signature,result_type,nargs,returns_set,names) LEFT JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||e.signature)
 WHERE p.oid IS NULL OR p.prokind<>'f' OR p.prorettype<>e.result_type::regtype OR p.proretset<>e.returns_set
 OR p.proisstrict OR p.proleakproof OR p.proparallel<>'u' OR p.pronargs<>e.nargs OR p.pronargdefaults<>0 OR p.provariadic<>0
 OR p.proargnames IS DISTINCT FROM e.names OR p.prolang<>(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
 OR (NOT e.returns_set AND (p.proargmodes IS NOT NULL OR p.proallargtypes IS NOT NULL))) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc WHERE oid='kaname.authority_forward_claim_v4(uuid)'::regprocedure
  AND proretset AND prorettype='record'::regtype AND pronargs=1
  AND proargnames=ARRAY['p_nonce','id','event_type','payload','created_at']
  AND proargmodes=ARRAY['i','t','t','t','t']::"char"[]
  AND proallargtypes=ARRAY['uuid'::regtype::oid,'bigint'::regtype::oid,'text'::regtype::oid,'jsonb'::regtype::oid,'timestamptz'::regtype::oid]) THEN RETURN false;END IF;
 RETURN true;
END $$;

DO $$ DECLARE f record;r record;BEGIN
 FOR f IN SELECT p.oid,p.oid::regprocedure signature,p.proowner FROM pg_catalog.pg_proc p
 WHERE p.pronamespace='kaname'::regnamespace AND p.proname IN (
  'authority_native_delete_emit_v4','authority_native_delete_prepare_v4','authority_native_delete_stamp_v4',
  'authority_forward_emit_v4','authority_forward_prepare_v4','authority_forward_claim_v4','authority_forward_finish_v4',
  '_authority_forward_custody_v4','_authority_forward_shape_v4','_authority_forward_context_v4','_authority_forward_program_v4',
  '_authority_forward_row_v4','_authority_forward_complete_v4','_authority_forward_anchor_complete_v4','_authority_forward_storage_v4') LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f.signature);
  FOR r IN SELECT DISTINCT u.rolname FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
   JOIN pg_catalog.pg_roles u ON u.oid=a.grantee WHERE p.oid=f.oid AND a.grantee<>f.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',f.signature,r.rolname);
  END LOOP;
 END LOOP;
END $$;

-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Замкнутый graph двух actual таблиц: лишний callback недопустим даже тогда,
-- когда все ожидаемые attachments по отдельности присутствуют.
CREATE FUNCTION kaname._authority_native_delete_batch_graph_v4() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid IN ('kaname.fga_outbox'::regclass,'kaname.relation_fact'::regclass)
  AND (relkind<>'r' OR relpersistence<>'p' OR relrowsecurity OR relforcerowsecurity OR relhasrules OR relhassubclass
   OR relowner<>(SELECT relowner FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass)))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid IN ('kaname.fga_outbox'::regclass,'kaname.relation_fact'::regclass)
  OR inhparent IN ('kaname.fga_outbox'::regclass,'kaname.relation_fact'::regclass)) THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM (VALUES
  ('fga_outbox','authority_protocol_statement','authority_protocol_statement_guard()',62,NULL::text,NULL::text),
  ('fga_outbox','authority_protocol_row','authority_protocol_row_guard()',31,NULL,NULL),
  ('fga_outbox','authority_resource_effect_applied','_authority_resource_effect_applied_v2()',29,NULL,NULL),
  ('fga_outbox','policy_epoch_insert','authority_policy_changed()',4,NULL,'new_policy_rows'),
  ('fga_outbox','policy_epoch_update','authority_policy_changed()',16,'old_policy_rows','new_policy_rows'),
  ('fga_outbox','policy_epoch_delete','authority_policy_changed()',8,'old_policy_rows',NULL),
  ('fga_outbox','authority_crud_sequence','authority_crud_sequence_guard_v3()',23,NULL,NULL),
  ('fga_outbox','authority_crud_fga_id_guard','authority_crud_fga_id_guard_v3()',7,NULL,NULL),
  ('fga_outbox','authority_crud_fga_id_applied','authority_crud_fga_id_applied_v3()',5,NULL,NULL),
  ('fga_outbox','authority_sequence_program_applied_v3','authority_sequence_program_applied_v3()',5,NULL,NULL),
  ('fga_outbox','relation_fact_00_native_batch','_authority_native_delete_batch_begin_v4()',4,NULL,'journal_rows'),
  ('fga_outbox','relation_fact_follows_journal','relation_fact_from_journal()',4,NULL,'journal_rows'),
  ('fga_outbox','relation_fact_zz_native_batch','_authority_native_delete_batch_end_v4()',4,NULL,'journal_rows'),
  ('relation_fact','authority_protocol_statement','authority_protocol_statement_guard()',62,NULL,NULL),
  ('relation_fact','authority_protocol_row','authority_protocol_row_guard()',31,NULL,NULL),
  ('relation_fact','authority_resource_effect_applied','_authority_resource_effect_applied_v2()',29,NULL,NULL),
  ('relation_fact','policy_epoch_insert','authority_policy_changed()',4,NULL,'new_policy_rows'),
  ('relation_fact','policy_epoch_update','authority_policy_changed()',16,'old_policy_rows','new_policy_rows'),
  ('relation_fact','policy_epoch_delete','authority_policy_changed()',8,'old_policy_rows',NULL),
  ('relation_fact','policy_epoch_truncate','authority_policy_changed()',32,NULL,NULL)
 ) e(table_name,trigger_name,signature,trigger_type,old_table,new_table)
 FULL JOIN (SELECT t.* FROM pg_catalog.pg_trigger t WHERE t.tgrelid IN
  ('kaname.fga_outbox'::regclass,'kaname.relation_fact'::regclass)) t
 ON t.tgrelid=to_regclass('kaname.'||e.table_name) AND t.tgname=e.trigger_name
 WHERE e.trigger_name IS NULL OR t.oid IS NULL OR t.tgfoid<>to_regprocedure('kaname.'||e.signature)
  OR t.tgtype::integer<>e.trigger_type OR t.tgenabled<>'O' OR t.tgisinternal
  OR t.tgconstraint<>0 OR t.tgdeferrable OR t.tginitdeferred OR t.tgnargs<>0 OR t.tgargs<>''::bytea
  OR t.tgattr<>''::int2vector OR t.tgqual IS NOT NULL
  OR t.tgoldtable::text IS DISTINCT FROM e.old_table OR t.tgnewtable::text IS DISTINCT FROM e.new_table) THEN RETURN false;END IF;
 RETURN true;
END $$;

-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Native DELETE: owner удостоверяет только происхождение; факт меняет invoker.
CREATE FUNCTION kaname.authority_native_delete_batch_read_v4() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a kaname.authority_forward_emit_anchor_v4%ROWTYPE;program jsonb;result jsonb;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM kaname.authority_forward_emit_anchor_v4 WHERE backend=pg_backend_pid()
  AND transaction_id=pg_current_xact_id_if_assigned() AND (batch_required OR batch<>'{}'::jsonb)) THEN RETURN NULL;END IF;
 IF NOT kaname._authority_forward_storage_v4() OR NOT kaname._authority_native_delete_batch_graph_v4() THEN RAISE EXCEPTION 'native batch anchor custody changed' USING ERRCODE='42501';END IF;
 FOR a IN SELECT * FROM kaname.authority_forward_emit_anchor_v4
 WHERE backend=pg_backend_pid() AND transaction_id=pg_current_xact_id_if_assigned() AND (batch_required OR batch<>'{}'::jsonb) LOOP
  program:=kaname._authority_forward_program_v4(a.nonce);
  IF NOT a.batch_required OR coalesce(a.batch->>'phase' NOT IN ('deleting','policy-complete','finished'),true)
   OR a.batch->>'nonce' IS DISTINCT FROM a.nonce::text
   OR a.batch->>'digest' IS DISTINCT FROM encode(sha256(convert_to((a.batch->'rows')::text,'UTF8')),'hex')
   OR jsonb_typeof(a.batch->'rows') IS DISTINCT FROM 'array'
   OR jsonb_array_length(a.batch->'rows') IS DISTINCT FROM a.effect_count THEN
   RAISE EXCEPTION 'native batch anchor changed' USING ERRCODE='42501';END IF;
  IF a.batch->>'phase'='finished' THEN CONTINUE;END IF;
  IF result IS NOT NULL OR a.finished OR program->>'phase'<>'claimed' THEN
   RAISE EXCEPTION 'native batch invocation overlaps or changed' USING ERRCODE='42501';END IF;
  IF pg_trigger_depth()=0 THEN RAISE EXCEPTION 'native batch outside trigger invocation' USING ERRCODE='42501';END IF;
  IF (SELECT proof FROM kaname._authority_protocol_snapshot_v3()) IS NOT NULL
   OR current_setting('transaction_isolation')<>'read committed'
   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid()
    AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
    AND classid=1262569292 AND objid=0 AND objsubid=2 AND mode='ExclusiveLock' AND granted) THEN
   RAISE EXCEPTION 'native batch unsigned admission lost' USING ERRCODE='42501';END IF;
  result:=a.batch;
 END LOOP;
 RETURN result;
END $$;

-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- WRITE имеет собственные обязательства. Старые prepare/claim их не создают.
CREATE FUNCTION kaname._authority_native_write_weights_v4(p_rows jsonb) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE result jsonb;
BEGIN
 -- DISTINCT принадлежит одной исторической строке, SUM -- разным строкам.
 WITH per_row AS MATERIALIZED (
  SELECT j,ARRAY(SELECT DISTINCT k COLLATE "C" FROM unnest(kaname.authority_policy_keys('relation_fact',j)) k) keys
  FROM jsonb_array_elements(p_rows) j),
 weights AS (SELECT k,count(*) n FROM per_row CROSS JOIN LATERAL unnest(keys) k GROUP BY k)
 SELECT CASE WHEN EXISTS(SELECT 1 FROM per_row WHERE '*'=ANY(keys) OR cardinality(keys)>4096)
  THEN NULL ELSE coalesce((SELECT jsonb_object_agg(k,n) FROM weights),'{}'::jsonb) END INTO result;
 RETURN result;
END $$;

CREATE FUNCTION kaname._authority_native_write_closure_v4() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NOT kaname._authority_full_contract_storage_v3() OR NOT kaname._authority_native_delete_batch_graph_v4() THEN RETURN false;END IF;
 -- Builtin identity для типов/операторов/defaults, влияющих на actual DML.
 IF EXISTS(SELECT 1 FROM (VALUES ('text','textin','textout'),('jsonb','jsonb_in','jsonb_out'),
   ('timestamptz','timestamptz_in','timestamptz_out'),('int8','int8in','int8out')) e(typ,inp,outp)
  LEFT JOIN pg_catalog.pg_type t ON t.oid=to_regtype('pg_catalog.'||e.typ)
  LEFT JOIN pg_catalog.pg_proc i ON i.oid=t.typinput LEFT JOIN pg_catalog.pg_proc o ON o.oid=t.typoutput
  WHERE t.oid IS NULL OR t.typtype<>'b' OR NOT t.typisdefined OR t.typbasetype<>0
   OR i.pronamespace<>'pg_catalog'::regnamespace OR i.prosrc<>e.inp OR i.prosecdef OR i.proconfig IS NOT NULL
   OR o.pronamespace<>'pg_catalog'::regnamespace OR o.prosrc<>e.outp OR o.prosecdef OR o.proconfig IS NOT NULL
   OR i.prolang<>(SELECT oid FROM pg_catalog.pg_language WHERE lanname='internal')
   OR o.prolang<>(SELECT oid FROM pg_catalog.pg_language WHERE lanname='internal'))
 OR EXISTS(SELECT 1 FROM (VALUES ('=(text,text)','texteq'),('<>(text,text)','textne'),('<(text,text)','text_lt'),
   ('!~~(text,text)','textnlike'),('!~(text,text)','textregexne'),('=(jsonb,jsonb)','jsonb_eq'),
   ('<(timestamptz,timestamptz)','timestamp_lt'),('>=(bigint,bigint)','int8ge')) e(op,src)
  LEFT JOIN pg_catalog.pg_operator o ON o.oid=to_regoperator('pg_catalog.'||e.op)
  LEFT JOIN pg_catalog.pg_proc f ON f.oid=o.oprcode WHERE o.oid IS NULL OR f.oid IS NULL
   OR f.pronamespace<>'pg_catalog'::regnamespace OR f.prosrc<>e.src OR f.prosecdef OR f.proconfig IS NOT NULL
   OR f.prolang<>(SELECT oid FROM pg_catalog.pg_language WHERE lanname='internal'))
 OR EXISTS(SELECT 1 FROM (VALUES ('now()','now'),('jsonb_typeof(jsonb)','jsonb_typeof'),
   ('split_part(text,text,integer)','split_part'),('pg_current_xact_id()','pg_current_xact_id')) e(sig,src)
  LEFT JOIN pg_catalog.pg_proc f ON f.oid=to_regprocedure('pg_catalog.'||e.sig)
  WHERE f.oid IS NULL OR f.prosrc<>e.src OR f.prosecdef OR f.proconfig IS NOT NULL
   OR f.prolang<>(SELECT oid FROM pg_catalog.pg_language WHERE lanname='internal')) THEN RETURN false;END IF;
 -- Ровно builtin columns: domain/input/default hooks не становятся частью batch.
 IF EXISTS(SELECT 1 FROM (VALUES
  ('relation_fact',1,'object_type','text',NULL::text),('relation_fact',2,'object_id','text',NULL),
  ('relation_fact',3,'relation','text',NULL),('relation_fact',4,'subject','text',NULL),
  ('relation_fact',5,'source_version','timestamptz','''-infinity''::timestamp with time zone'),
  ('relation_fact',6,'created_at','timestamptz','now()'),('relation_fact',7,'condition_name','text','''''::text'),
  ('relation_fact',8,'condition_params','jsonb','''{}''::jsonb'),
  ('fga_outbox',1,'id','bigint','kaname.authority_fga_outbox_id_v3()'),
  ('fga_outbox',2,'event_type','text',NULL),('fga_outbox',3,'payload','jsonb',NULL),
  ('fga_outbox',4,'created_at','timestamptz','now()')) e(tbl,num,name,typ,def)
 FULL JOIN (SELECT a.*,d.adbin FROM pg_catalog.pg_attribute a LEFT JOIN pg_catalog.pg_attrdef d
  ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid IN
   ('kaname.relation_fact'::regclass,'kaname.fga_outbox'::regclass) AND a.attnum>0) a
 ON a.attrelid=to_regclass('kaname.'||e.tbl) AND a.attnum=e.num
 WHERE e.tbl IS NULL OR a.attrelid IS NULL OR a.attisdropped OR NOT a.attnotnull
  OR a.attname<>e.name OR a.atttypid<>to_regtype('pg_catalog.'||e.typ) OR a.atttypmod<>-1
  OR a.attgenerated<>'' OR a.attidentity<>'' OR a.attinhcount<>0 OR NOT a.attislocal
  OR a.attcollation<>CASE WHEN e.typ='text' THEN 'pg_catalog."default"'::regcollation::oid ELSE 0 END
  OR pg_get_expr(a.adbin,a.attrelid) IS DISTINCT FROM e.def) THEN RETURN false;END IF;
 -- Полный индексный набор; никаких expression/opclass callbacks.
 IF EXISTS(SELECT 1 FROM (VALUES
  ('relation_fact','relation_fact_pkey','1 2 3 4',true,NULL::text),
  ('relation_fact','relation_fact_by_subject','4 3',false,NULL),
  ('relation_fact','relation_fact_conditioned','7',false,'(condition_name <> ''''::text)'),
  ('fga_outbox','fga_outbox_pkey','1',true,NULL)) e(tbl,name,keys,pk,pred)
 FULL JOIN (SELECT i.*,c.relname,c.relam FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
  WHERE i.indrelid IN ('kaname.relation_fact'::regclass,'kaname.fga_outbox'::regclass)) i
 ON i.indrelid=to_regclass('kaname.'||e.tbl) AND i.relname=e.name
 WHERE e.tbl IS NULL OR i.indexrelid IS NULL OR i.indkey::text<>e.keys OR i.indisprimary<>e.pk OR i.indisunique<>e.pk
  OR NOT i.indisvalid OR NOT i.indisready OR NOT i.indislive OR NOT i.indimmediate
  OR i.indnatts<>i.indnkeyatts OR i.indexprs IS NOT NULL OR i.indisexclusion
  OR i.relam<>(SELECT oid FROM pg_catalog.pg_am WHERE amname='btree')
  OR pg_get_expr(i.indpred,i.indrelid) IS DISTINCT FROM e.pred
  OR EXISTS(SELECT 1 FROM unnest(i.indclass) op LEFT JOIN pg_catalog.pg_opclass c ON c.oid=op
   WHERE c.opcnamespace<>'pg_catalog'::regnamespace OR c.opcname<>CASE WHEN e.tbl='fga_outbox' THEN 'int8_ops' ELSE 'text_ops' END)
  OR EXISTS(SELECT 1 FROM unnest(i.indoption) opt WHERE opt<>0)) THEN RETURN false;END IF;
 -- Существующие CHECK остаются actual executor checks; произвольный новый
 -- callback в CHECK не допускается даже если он пропускает эти две строки.
 IF EXISTS(SELECT 1 FROM (VALUES
  ('relation_fact','relation_fact_condition_params_is_object','(jsonb_typeof(condition_params) = ''object''::text)'),
  ('relation_fact','relation_fact_object_id_nonempty','(object_id <> ''''::text)'),
  ('relation_fact','relation_fact_object_type_model_dictionary','(object_type !~~ ''%.%''::text)'),
  ('relation_fact','relation_fact_object_type_nonempty','(object_type <> ''''::text)'),
  ('relation_fact','relation_fact_params_require_condition','((condition_name <> ''''::text) OR (condition_params = ''{}''::jsonb))'),
  ('relation_fact','relation_fact_relation_nonempty','(relation <> ''''::text)'),
  ('relation_fact','relation_fact_subject_nonempty','(subject <> ''''::text)'),
  ('relation_fact','relation_fact_subject_not_wildcard','(subject !~ '':\*($|#)''::text)'),
  ('relation_fact','relation_fact_subject_class_reads_only','((split_part(subject, '':''::text, 1) <> ''system_class''::text) OR ((subject = ANY (ARRAY[''system_class:anonymous''::text, ''system_class:authenticated''::text])) AND (relation = ANY (ARRAY[''v_get''::text, ''viewer''::text, ''system_viewer''::text, ''public_reader''::text]))))'),
  ('relation_fact','relation_fact_public_reader_subject_is_class','((relation <> ''public_reader''::text) OR (subject = ANY (ARRAY[''system_class:anonymous''::text, ''system_class:authenticated''::text])))'),
  ('fga_outbox','fga_outbox_event_type_check','(event_type = ANY (ARRAY[''fga.tuple.write''::text, ''fga.tuple.delete''::text]))'),
  ('fga_outbox','fga_outbox_relation_present_check','((((payload ->> ''relation''::text) IS NOT NULL) AND ((payload ->> ''relation''::text) <> ''''::text)) OR (jsonb_array_length(COALESCE((payload -> ''relations''::text), ''[]''::jsonb)) > 0))')) e(tbl,name,expr)
 FULL JOIN (SELECT * FROM pg_catalog.pg_constraint WHERE conrelid IN
  ('kaname.relation_fact'::regclass,'kaname.fga_outbox'::regclass) AND contype<>'p') c
 ON c.conrelid=to_regclass('kaname.'||e.tbl) AND c.conname=e.name
 WHERE e.tbl IS NULL OR c.oid IS NULL OR c.contype<>'c' OR c.condeferrable OR c.condeferred OR c.connoinherit
  OR c.coninhcount<>0 OR NOT c.conislocal OR (NOT c.convalidated AND c.conname<>'fga_outbox_relation_present_check')
  OR pg_get_expr(c.conbin,c.conrelid) IS DISTINCT FROM e.expr) THEN RETURN false;END IF;
 -- Epoch UPSERT тоже сокращает физическую multiplicity: разрешены только
 -- прежние monotonic callbacks, canonical private storage и builtin defaults.
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid='kaname.authority_policy_epoch'::regclass
  AND relowner=(SELECT relowner FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass)
  AND relkind='r' AND relpersistence='p' AND NOT relrowsecurity AND NOT relforcerowsecurity AND NOT relhasrules AND NOT relhassubclass)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid='kaname.authority_policy_epoch'::regclass OR inhparent='kaname.authority_policy_epoch'::regclass)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
  WHERE c.oid='kaname.authority_policy_epoch'::regclass AND a.grantee<>c.relowner)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) x
  WHERE a.attrelid='kaname.authority_policy_epoch'::regclass AND x.grantee<>(SELECT relowner FROM pg_catalog.pg_class WHERE oid=a.attrelid))
 OR EXISTS(SELECT 1 FROM (VALUES ('authority_policy_epoch_monotonic_v2',27),('authority_policy_epoch_no_truncate_v2',34)) e(name,kind)
  FULL JOIN (SELECT * FROM pg_catalog.pg_trigger WHERE tgrelid='kaname.authority_policy_epoch'::regclass) t ON t.tgname=e.name
  WHERE e.name IS NULL OR t.oid IS NULL OR t.tgtype::integer<>e.kind OR t.tgenabled<>'O' OR t.tgisinternal
   OR t.tgfoid<>'kaname.authority_policy_epoch_monotonic_v2()'::regprocedure OR t.tgconstraint<>0
   OR t.tgdeferrable OR t.tginitdeferred OR t.tgnargs<>0 OR t.tgargs<>''::bytea OR t.tgattr<>''::int2vector
   OR t.tgqual IS NOT NULL OR t.tgoldtable IS NOT NULL OR t.tgnewtable IS NOT NULL)
 OR EXISTS(SELECT 1 FROM (VALUES (1,'key','text',NULL::text),(2,'revision','int8','0'),
   (3,'generation','text','(pg_current_xact_id())::text')) e(num,name,typ,def)
  FULL JOIN (SELECT a.*,d.adbin FROM pg_catalog.pg_attribute a LEFT JOIN pg_catalog.pg_attrdef d
   ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='kaname.authority_policy_epoch'::regclass AND a.attnum>0) a ON a.attnum=e.num
  WHERE e.num IS NULL OR a.attnum IS NULL OR a.attisdropped OR NOT a.attnotnull OR a.attname<>e.name
   OR a.atttypid<>to_regtype('pg_catalog.'||e.typ) OR a.atttypmod<>-1 OR a.attgenerated<>'' OR a.attidentity<>''
   OR a.attinhcount<>0 OR NOT a.attislocal OR pg_get_expr(a.adbin,a.attrelid) IS DISTINCT FROM e.def)
 OR (SELECT count(*) FROM pg_catalog.pg_constraint WHERE conrelid='kaname.authority_policy_epoch'::regclass)<>2
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid='kaname.authority_policy_epoch'::regclass
  AND contype='c' AND conname='authority_policy_epoch_revision_check' AND convalidated AND NOT condeferrable
  AND NOT condeferred AND pg_get_expr(conbin,conrelid)='(revision >= 0)')
 OR (SELECT count(*) FROM pg_catalog.pg_index WHERE indrelid='kaname.authority_policy_epoch'::regclass)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
  WHERE i.indrelid='kaname.authority_policy_epoch'::regclass AND i.indisprimary AND i.indisunique AND i.indisvalid
   AND i.indisready AND i.indislive AND i.indimmediate AND i.indkey='1'::int2vector AND i.indnkeyatts=1 AND i.indnatts=1
   AND i.indexprs IS NULL AND i.indpred IS NULL AND NOT i.indisexclusion
   AND c.relam=(SELECT oid FROM pg_catalog.pg_am WHERE amname='btree')
   AND i.indclass=ARRAY[(SELECT oid FROM pg_catalog.pg_opclass WHERE opcnamespace='pg_catalog'::regnamespace
    AND opcname='text_ops' AND opcmethod=c.relam)]::oidvector AND i.indoption='0'::int2vector)
 THEN RETURN false;END IF;
 RETURN true;
END $$;

-- Единственная новая изменяющая private state возможность принимает только nonce.
-- Owner не пишет факты и не возвращает owner fact images/результат отсутствия.
CREATE FUNCTION kaname.authority_native_write_arm_v4(p_nonce uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE program jsonb;invoker oid;rows_value jsonb;facts jsonb;weights jsonb;epochs jsonb;expected integer;
 fallback_requested boolean:=false;published boolean:=false;
BEGIN
 invoker:=kaname._authority_forward_context_v4();
 program:=kaname._authority_forward_program_v4(p_nonce);expected:=(program->>'effect_count')::integer;
 IF program->>'phase'<>'prepared' OR EXISTS(SELECT 1 FROM kaname.authority_forward_emit_anchor_v4
  WHERE backend=pg_backend_pid() AND transaction_id=pg_current_xact_id() AND (write_required OR write_batch<>'{}'::jsonb)
   AND (nonce=p_nonce OR write_batch->>'phase' IS DISTINCT FROM 'finished')) THEN
  RAISE EXCEPTION 'native write arm replay or overlap' USING ERRCODE='42501';END IF;
 IF expected=0 OR current_setting('transaction_isolation')<>'read committed' THEN RETURN;END IF;
 IF kaname._authority_group_add_program_v3() IS NOT NULL OR kaname._authority_producer_resource_v2() IS NOT NULL
  OR kaname._authority_binding_mirror_store_v3() IS NOT NULL THEN RETURN;END IF;
 -- Comma-list в has_table_privilege означает OR: здесь именно три AND.
 IF NOT has_table_privilege(invoker,'kaname.relation_fact'::regclass,'SELECT')
  OR NOT has_table_privilege(invoker,'kaname.relation_fact'::regclass,'INSERT')
  OR NOT has_table_privilege(invoker,'kaname.relation_fact'::regclass,'UPDATE')
  OR NOT has_function_privilege(invoker,'kaname.authority_native_write_read_v4()','EXECUTE') THEN RETURN;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid()
  AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
  AND classid=1262569292 AND objid=0 AND objsubid=2 AND mode='ExclusiveLock' AND granted) THEN
  RAISE EXCEPTION 'native write exclusive admission missing' USING ERRCODE='42501';END IF;
 IF NOT kaname._authority_native_write_closure_v4() THEN RETURN;END IF;
 SELECT jsonb_agg(e.row_value||jsonb_build_object('id',e.reserved_id) ORDER BY e.reserved_id) INTO rows_value
 FROM pg_temp.kaname_forward_effects_v4 e WHERE e.nonce=p_nonce;
 IF jsonb_array_length(rows_value) IS DISTINCT FROM expected OR EXISTS(
  SELECT 1 FROM pg_temp.kaname_forward_effects_v4 e FULL JOIN
   (SELECT * FROM pg_temp.kaname_forward_receipts_v4 WHERE nonce=p_nonce) r ON e.nonce=r.nonce AND e.ordinal=r.ordinal
  WHERE (e.nonce=p_nonce OR e.nonce IS NULL) AND (e.nonce IS NULL OR r.nonce IS NULL
   OR e.reserved_id IS DISTINCT FROM r.reserved_id OR e.ordinal<1 OR e.ordinal>expected
   OR e.row_digest IS DISTINCT FROM sha256(convert_to(e.row_value::text,'UTF8'))
   OR r.backend IS DISTINCT FROM pg_backend_pid() OR r.transaction_id IS DISTINCT FROM pg_current_xact_id()
   OR r.invoker_oid IS DISTINCT FROM invoker OR r.program_oid IS DISTINCT FROM (program->>'program_oid')::oid
   OR r.effects_oid IS DISTINCT FROM (program->>'effects_oid')::oid OR r.table_oid IS DISTINCT FROM 'kaname.fga_outbox'::regclass::oid
   OR r.key_namespace IS DISTINCT FROM 1262569305 OR r.key_hash IS DISTINCT FROM hashtext(e.reserved_id::text)
   OR r.objsubid IS DISTINCT FROM 2 OR r.lock_mode IS DISTINCT FROM 'ExclusiveLock'
   OR r.claimed IS DISTINCT FROM false OR r.guarded IS DISTINCT FROM false OR r.consumed IS DISTINCT FROM false)) THEN
  RAISE EXCEPTION 'native write prepared receipts changed' USING ERRCODE='42501';END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(rows_value) j WHERE j->>'event_type' IS DISTINCT FROM 'fga.tuple.write'
  OR j->>'created_at' IS NULL OR (j->>'created_at')::timestamptz IS DISTINCT FROM transaction_timestamp()
  OR nullif(j#>'{payload,source_version}','null'::jsonb) IS NOT NULL
  OR j#>>'{payload,user}' IS NULL OR j#>>'{payload,user}' !~ '^user:[^#*]+$'
  OR j#>>'{payload,object}' IS NULL OR j#>>'{payload,object}' !~ '^(compute_instance|account):[^:]+$'
  OR (CASE WHEN jsonb_typeof(coalesce(j#>'{payload,relations}','[]'::jsonb))='array' THEN
   CASE WHEN jsonb_array_length(coalesce(j#>'{payload,relations}','[]'::jsonb))>0 THEN
    ARRAY(SELECT value FROM jsonb_array_elements_text(j#>'{payload,relations}') value WHERE value NOT LIKE 'v\_%' ORDER BY value COLLATE "C")
   ELSE ARRAY[j#>>'{payload,relation}'] END ELSE NULL END) IS DISTINCT FROM ARRAY['editor'])
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(rows_value) j GROUP BY j#>>'{payload,object}',j#>>'{payload,user}' HAVING count(*)<>1) THEN RETURN;END IF;
 SELECT jsonb_agg(jsonb_build_object('object_type',split_part(j#>>'{payload,object}',':',1),
  'object_id',split_part(j#>>'{payload,object}',':',2),'relation','editor','subject',j#>>'{payload,user}',
  'source_version',(j->>'created_at')::timestamptz,'created_at',transaction_timestamp(),'condition_name','','condition_params','{}'::jsonb)
  ORDER BY j#>>'{payload,object}' COLLATE "C",j#>>'{payload,user}' COLLATE "C",(j->>'id')::bigint) INTO facts
 FROM jsonb_array_elements(rows_value) j;
 -- Только после всех исходных full-table прав и canonical no-RLS closure.
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(facts) j JOIN kaname.relation_fact f
  ON f.object_type=j->>'object_type' AND f.object_id=j->>'object_id' AND f.relation=j->>'relation' AND f.subject=j->>'subject') THEN RETURN;END IF;
 weights:=kaname._authority_native_write_weights_v4(facts);IF weights IS NULL THEN RETURN;END IF;
 -- Никаких fact row locks в all-absent ветке. Существующий exclusive barrier
 -- уже исключает другие canonical writers до lock policy; после waits читаем заново.
 BEGIN
  PERFORM key FROM kaname.authority_policy_epoch WHERE key='*' FOR SHARE NOWAIT;
  PERFORM e.key FROM kaname.authority_policy_epoch e JOIN jsonb_each_text(weights) w ON w.key=e.key ORDER BY e.key COLLATE "C" FOR UPDATE OF e NOWAIT;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(facts) j JOIN kaname.relation_fact f
  ON f.object_type=j->>'object_type' AND f.object_id=j->>'object_id' AND f.relation=j->>'relation' AND f.subject=j->>'subject') THEN
  fallback_requested:=true;
  RAISE EXCEPTION 'native write pre-arm eligibility fallback' USING ERRCODE='ZFW01';
 END IF;
 IF weights IS DISTINCT FROM kaname._authority_native_write_weights_v4(facts) THEN
  fallback_requested:=true;
  RAISE EXCEPTION 'native write pre-arm eligibility fallback' USING ERRCODE='ZFW01';
 END IF;
 IF EXISTS(SELECT 1 FROM jsonb_each_text(weights) w JOIN kaname.authority_policy_epoch e ON e.key=w.key
  WHERE e.revision>9223372036854775807::bigint-w.value::bigint) THEN
  fallback_requested:=true;
  RAISE EXCEPTION 'native write pre-arm eligibility fallback' USING ERRCODE='ZFW01';
 END IF;
 SELECT coalesce(jsonb_object_agg(w.key,to_jsonb(e)),'{}'::jsonb) INTO epochs
 FROM (SELECT key FROM jsonb_each_text(weights) UNION ALL SELECT '*') w LEFT JOIN kaname.authority_policy_epoch e ON e.key=w.key;
 UPDATE kaname.authority_forward_emit_anchor_v4 SET write_required=true,write_batch=jsonb_build_object(
  'nonce',p_nonce,'phase','armed','rows',rows_value,'facts',facts,'weights',weights,'epochs',epochs,
  'attempted_insert',expected,'empty_update',expected,'actual_new',expected,
  'digest',encode(sha256(convert_to(jsonb_build_array(rows_value,facts,weights,epochs)::text,'UTF8')),'hex'))
 WHERE backend=pg_backend_pid() AND transaction_id=pg_current_xact_id() AND nonce=p_nonce
  AND NOT finished AND NOT write_required AND write_batch='{}'::jsonb AND NOT batch_required AND batch='{}'::jsonb;
 IF NOT FOUND THEN RAISE EXCEPTION 'native write arm anchor changed' USING ERRCODE='42501';END IF;
 published:=true;
 EXCEPTION
 WHEN lock_not_available THEN
  -- Speculative NOWAIT: откат ВСЕХ приобретений до любого generic fallback.
  IF published THEN RAISE;END IF;
  RETURN;
 WHEN SQLSTATE 'ZFW01' THEN
  -- Только наш непосредственный отказ до публикации. Чужая ошибка с тем же
  -- SQLSTATE и любой отказ после публикации не превращаются в fallback.
  IF NOT fallback_requested OR published THEN RAISE;END IF;
  RETURN;
 END;
END $$;

CREATE FUNCTION kaname.authority_native_write_read_v4() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a kaname.authority_forward_emit_anchor_v4%ROWTYPE;program jsonb;result jsonb;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM kaname.authority_forward_emit_anchor_v4 WHERE backend=pg_backend_pid()
  AND transaction_id=pg_current_xact_id_if_assigned() AND (write_required OR write_batch<>'{}'::jsonb)) THEN RETURN NULL;END IF;
 IF NOT kaname._authority_native_write_closure_v4() THEN RAISE EXCEPTION 'native write executable closure changed' USING ERRCODE='42501';END IF;
 FOR a IN SELECT * FROM kaname.authority_forward_emit_anchor_v4 WHERE backend=pg_backend_pid()
  AND transaction_id=pg_current_xact_id_if_assigned() AND (write_required OR write_batch<>'{}'::jsonb) LOOP
  program:=kaname._authority_forward_program_v4(a.nonce);
  IF NOT a.write_required OR a.batch_required OR a.batch<>'{}'::jsonb
   OR a.write_batch->>'nonce' IS DISTINCT FROM a.nonce::text
   OR coalesce(a.write_batch->>'phase' NOT IN ('armed','inserting','empty-update','policy-complete','finished'),true)
   OR a.write_batch->>'digest' IS DISTINCT FROM encode(sha256(convert_to(jsonb_build_array(a.write_batch->'rows',
    a.write_batch->'facts',a.write_batch->'weights',a.write_batch->'epochs')::text,'UTF8')),'hex')
   OR jsonb_typeof(a.write_batch->'rows') IS DISTINCT FROM 'array' OR jsonb_typeof(a.write_batch->'facts') IS DISTINCT FROM 'array'
   OR jsonb_array_length(a.write_batch->'rows') IS DISTINCT FROM a.effect_count
   OR jsonb_array_length(a.write_batch->'facts') IS DISTINCT FROM a.effect_count
   OR a.write_batch->'attempted_insert' IS DISTINCT FROM to_jsonb(a.effect_count)
   OR a.write_batch->'empty_update' IS DISTINCT FROM to_jsonb(a.effect_count)
   OR a.write_batch->'actual_new' IS DISTINCT FROM to_jsonb(a.effect_count) THEN
   RAISE EXCEPTION 'native write immutable obligations changed' USING ERRCODE='42501';END IF;
  IF a.write_batch->>'phase'='finished' THEN CONTINUE;END IF;
  IF result IS NOT NULL OR a.finished OR program->>'phase' NOT IN ('prepared','claimed') OR pg_trigger_depth()=0 THEN
   RAISE EXCEPTION 'native write invocation overlaps or changed' USING ERRCODE='42501';END IF;
  IF (SELECT proof FROM kaname._authority_protocol_snapshot_v3()) IS NOT NULL OR current_setting('transaction_isolation')<>'read committed'
   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid()
    AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
    AND classid=1262569292 AND objid=0 AND objsubid=2 AND mode='ExclusiveLock' AND granted) THEN
   RAISE EXCEPTION 'native write unsigned admission lost' USING ERRCODE='42501';END IF;
  IF NOT has_table_privilege(a.invoker_oid,'kaname.relation_fact'::regclass,'SELECT')
   OR NOT has_table_privilege(a.invoker_oid,'kaname.relation_fact'::regclass,'INSERT')
   OR NOT has_table_privilege(a.invoker_oid,'kaname.relation_fact'::regclass,'UPDATE') THEN
   RAISE EXCEPTION 'native write original privileges changed after arm' USING ERRCODE='42501';END IF;
  -- projection depth=1: owner-read не заменяет actual invoker UPSERT.
  -- Свежая проверка непосредственно перед ним ловит same-backend interference.
  IF a.write_batch->>'phase'='inserting' AND pg_trigger_depth()=1 AND EXISTS(
   SELECT 1 FROM jsonb_array_elements(a.write_batch->'facts') j JOIN kaname.relation_fact f
    ON f.object_type=j->>'object_type' AND f.object_id=j->>'object_id' AND f.relation=j->>'relation' AND f.subject=j->>'subject') THEN
   RAISE EXCEPTION 'native write absence changed after arm' USING ERRCODE='42501';END IF;
  result:=a.write_batch;
 END LOOP;
 RETURN result;
END $$;

CREATE FUNCTION kaname._authority_native_delete_batch_begin_v4() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE command_nonce uuid;program jsonb;rows_value jsonb;expected integer;candidate record;keys text[];batch_value jsonb;
BEGIN
 IF TG_RELID<>'kaname.fga_outbox'::regclass OR TG_OP<>'INSERT' OR TG_LEVEL<>'STATEMENT'
  OR TG_WHEN<>'AFTER' OR TG_NAME<>'relation_fact_00_native_batch' THEN
  RAISE EXCEPTION 'native batch initializer trigger changed' USING ERRCODE='42501';END IF;
 batch_value:=kaname.authority_native_write_read_v4();
 IF batch_value IS NOT NULL THEN
  IF batch_value->>'phase'<>'armed' THEN RAISE EXCEPTION 'native write initializer replay' USING ERRCODE='42501';END IF;
  command_nonce:=(batch_value->>'nonce')::uuid;
  program:=kaname._authority_forward_program_v4(command_nonce);expected:=(program->>'effect_count')::integer;
  SELECT jsonb_agg(to_jsonb(j) ORDER BY j.id) INTO rows_value FROM journal_rows j;
  IF rows_value IS DISTINCT FROM batch_value->'rows' THEN
   RAISE EXCEPTION 'native write whole journal transition differs' USING ERRCODE='42501';END IF;
 IF program->>'phase'<>'claimed' OR expected=0
 OR (SELECT count(*) FROM journal_rows)<>expected
 OR (SELECT count(*) FROM pg_temp.kaname_forward_effects_v4 WHERE nonce=command_nonce)<>expected
 OR (SELECT count(*) FROM pg_temp.kaname_forward_receipts_v4 WHERE nonce=command_nonce)<>expected
 OR EXISTS(SELECT 1 FROM journal_rows j FULL JOIN
  (SELECT e.*,r.backend,r.transaction_id,r.invoker_oid,r.program_oid,r.effects_oid,r.table_oid,r.key_namespace,
   r.key_hash,r.objsubid,r.lock_mode,r.claimed,r.guarded,r.consumed,r.reserved_id receipt_id,r.ordinal receipt_ordinal
   FROM pg_temp.kaname_forward_effects_v4 e LEFT JOIN pg_temp.kaname_forward_receipts_v4 r
    ON r.nonce=e.nonce AND r.ordinal=e.ordinal WHERE e.nonce=command_nonce) e ON e.reserved_id=j.id
  WHERE j.id IS NULL OR e.reserved_id IS NULL OR e.receipt_id IS DISTINCT FROM j.id OR e.receipt_ordinal IS DISTINCT FROM e.ordinal
   OR e.ordinal<1 OR e.ordinal>expected
   OR e.row_value IS DISTINCT FROM to_jsonb(j)-'id'
   OR e.row_digest IS DISTINCT FROM sha256(convert_to((to_jsonb(j)-'id')::text,'UTF8'))
   OR e.backend IS DISTINCT FROM pg_backend_pid() OR e.transaction_id IS DISTINCT FROM pg_current_xact_id()
   OR e.invoker_oid IS DISTINCT FROM (program->>'invoker_oid')::oid
   OR e.program_oid IS DISTINCT FROM (program->>'program_oid')::oid
   OR e.effects_oid IS DISTINCT FROM (program->>'effects_oid')::oid
   OR e.table_oid IS DISTINCT FROM 'kaname.fga_outbox'::regclass::oid
   OR e.key_namespace IS DISTINCT FROM 1262569305 OR e.key_hash IS DISTINCT FROM hashtext(j.id::text)
   OR e.objsubid IS DISTINCT FROM 2 OR e.lock_mode IS DISTINCT FROM 'ExclusiveLock'
   OR e.claimed IS DISTINCT FROM true OR e.guarded IS DISTINCT FROM true OR e.consumed IS DISTINCT FROM true) THEN
  RAISE EXCEPTION 'native write incomplete exact transition receipts' USING ERRCODE='42501';END IF;
  UPDATE kaname.authority_forward_emit_anchor_v4 SET write_batch=jsonb_set(write_batch,'{phase}','"inserting"'::jsonb)
  WHERE backend=pg_backend_pid() AND transaction_id=pg_current_xact_id() AND nonce=command_nonce
   AND NOT finished AND write_required AND write_batch->>'phase'='armed';
  IF NOT FOUND THEN RAISE EXCEPTION 'native write initializer anchor changed' USING ERRCODE='42501';END IF;
  RETURN NULL;
 END IF;
 -- Signed precedence и произвольный SQL не получают unsigned batch.
 IF kaname._authority_group_add_program_v3() IS NOT NULL
  OR kaname._authority_producer_resource_v2() IS NOT NULL
  OR kaname._authority_binding_mirror_store_v3() IS NOT NULL THEN RETURN NULL;END IF;
 -- WRITE/mixed оператор не платит за shape/count/digest batch-проверки.
 -- Прежние row receipts, generic fold и forward finish остаются на месте.
 IF EXISTS(SELECT 1 FROM journal_rows WHERE event_type IS DISTINCT FROM 'fga.tuple.delete') THEN RETURN NULL;END IF;
 -- Тот же исходный principal, что записан forward context, а не owner
 -- SECURITY DEFINER. Отсутствие нового read-only grant означает fallback.
 IF NOT has_function_privilege(coalesce(nullif(current_setting('role'),'none'),session_user),
  'kaname.authority_native_delete_batch_read_v4()','EXECUTE') THEN RETURN NULL;END IF;
 IF NOT EXISTS(SELECT 1 FROM kaname.authority_forward_emit_anchor_v4
  WHERE backend=pg_backend_pid() AND transaction_id=pg_current_xact_id_if_assigned() AND NOT finished) THEN RETURN NULL;END IF;
 PERFORM kaname._authority_forward_shape_v4();
 SELECT e.nonce INTO command_nonce FROM journal_rows j
 JOIN pg_temp.kaname_forward_effects_v4 e ON e.reserved_id=j.id LIMIT 1;
 IF command_nonce IS NULL THEN RETURN NULL;END IF;
 program:=kaname._authority_forward_program_v4(command_nonce);expected:=(program->>'effect_count')::integer;
 IF program->>'phase'<>'claimed' OR expected=0
 OR (SELECT count(*) FROM journal_rows)<>expected
 OR (SELECT count(*) FROM pg_temp.kaname_forward_effects_v4 WHERE nonce=command_nonce)<>expected
 OR (SELECT count(*) FROM pg_temp.kaname_forward_receipts_v4 WHERE nonce=command_nonce)<>expected
 OR EXISTS(SELECT 1 FROM journal_rows j FULL JOIN
  (SELECT e.*,r.backend,r.transaction_id,r.invoker_oid,r.program_oid,r.effects_oid,r.table_oid,r.key_namespace,
   r.key_hash,r.objsubid,r.lock_mode,r.claimed,r.guarded,r.consumed,r.reserved_id receipt_id,r.ordinal receipt_ordinal
   FROM pg_temp.kaname_forward_effects_v4 e LEFT JOIN pg_temp.kaname_forward_receipts_v4 r
    ON r.nonce=e.nonce AND r.ordinal=e.ordinal WHERE e.nonce=command_nonce) e ON e.reserved_id=j.id
  WHERE j.id IS NULL OR e.reserved_id IS NULL OR e.receipt_id IS DISTINCT FROM j.id OR e.receipt_ordinal IS DISTINCT FROM e.ordinal
   OR e.ordinal<1 OR e.ordinal>expected
   OR e.row_value IS DISTINCT FROM to_jsonb(j)-'id'
   OR e.row_digest IS DISTINCT FROM sha256(convert_to((to_jsonb(j)-'id')::text,'UTF8'))
   OR e.backend IS DISTINCT FROM pg_backend_pid() OR e.transaction_id IS DISTINCT FROM pg_current_xact_id()
   OR e.invoker_oid IS DISTINCT FROM (program->>'invoker_oid')::oid
   OR e.program_oid IS DISTINCT FROM (program->>'program_oid')::oid
   OR e.effects_oid IS DISTINCT FROM (program->>'effects_oid')::oid
   OR e.table_oid IS DISTINCT FROM 'kaname.fga_outbox'::regclass::oid
   OR e.key_namespace IS DISTINCT FROM 1262569305 OR e.key_hash IS DISTINCT FROM hashtext(j.id::text)
   OR e.objsubid IS DISTINCT FROM 2 OR e.lock_mode IS DISTINCT FROM 'ExclusiveLock'
   OR e.claimed IS DISTINCT FROM true OR e.guarded IS DISTINCT FROM true OR e.consumed IS DISTINCT FROM true) THEN
  RAISE EXCEPTION 'native batch incomplete exact transition receipts' USING ERRCODE='42501';END IF;
 IF current_setting('transaction_isolation')<>'read committed' THEN RETURN NULL;END IF;
 IF kaname.authority_protocol_attestation() IS NOT NULL THEN RETURN NULL;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid()
  AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
  AND classid=1262569292 AND objid=0 AND objsubid=2 AND mode='ExclusiveLock' AND granted) THEN
  RAISE EXCEPTION 'native batch exclusive admission missing' USING ERRCODE='42501';END IF;
 -- Консервативная первая дверь: одно effective editor после исходного verb filter, обычный user.
 -- Любая неподдержанная строка возвращает ВЕСЬ оператор прежней свёртке.
 IF EXISTS(SELECT 1 FROM journal_rows j WHERE j.event_type IS DISTINCT FROM 'fga.tuple.delete'
  OR j.created_at IS NULL OR nullif(j.payload->'source_version','null'::jsonb) IS NOT NULL
  OR (j.payload->>'user') IS NULL OR (j.payload->>'user') !~ '^user:[^#*]+$'
  OR (j.payload->>'object') IS NULL OR (j.payload->>'object') !~ '^(compute_instance|account):[^:]+$'
  OR (CASE WHEN jsonb_typeof(coalesce(j.payload->'relations','[]'::jsonb))='array' THEN
    CASE WHEN jsonb_array_length(coalesce(j.payload->'relations','[]'::jsonb))>0 THEN
     ARRAY(SELECT value FROM jsonb_array_elements_text(j.payload->'relations') value
      WHERE value NOT LIKE 'v\_%' ORDER BY value COLLATE "C")
    ELSE ARRAY[j.payload->>'relation'] END ELSE NULL END) IS DISTINCT FROM ARRAY['editor'])
 OR EXISTS(SELECT 1 FROM journal_rows GROUP BY payload->>'object',payload->>'user' HAVING count(*)<>1) THEN RETURN NULL;END IF;
 FOR candidate IN SELECT payload FROM journal_rows LOOP
  SELECT array_agg(DISTINCT k) INTO keys FROM unnest(kaname.authority_policy_keys('relation_fact',
   jsonb_build_object('object_type',split_part(candidate.payload->>'object',':',1),'object_id',split_part(candidate.payload->>'object',':',2),
    'relation','editor','subject',candidate.payload->>'user'))) k;
  IF '*'=ANY(keys) OR cardinality(keys)>4096 THEN RETURN NULL;END IF;
 END LOOP;
 -- Проверка исполняемого graph и ABI до публикации нового обязательства.
 IF NOT kaname._authority_full_contract_storage_v3() OR NOT kaname._authority_native_delete_batch_graph_v4() THEN
  RAISE EXCEPTION 'native batch executable closure changed' USING ERRCODE='42501';END IF;
 SELECT jsonb_agg(to_jsonb(j) ORDER BY j.id) INTO rows_value FROM journal_rows j;
 IF kaname.authority_native_delete_batch_read_v4() IS NOT NULL THEN
  RAISE EXCEPTION 'native batch nested command' USING ERRCODE='42501';END IF;
 UPDATE kaname.authority_forward_emit_anchor_v4 SET batch_required=true,batch=jsonb_build_object('nonce',command_nonce,
  'phase','deleting','rows',rows_value,'digest',encode(sha256(convert_to(rows_value::text,'UTF8')),'hex'))
 WHERE backend=pg_backend_pid() AND transaction_id=pg_current_xact_id() AND nonce=command_nonce AND NOT finished AND NOT batch_required AND batch='{}'::jsonb;
 IF NOT FOUND THEN RAISE EXCEPTION 'native batch anchor replay' USING ERRCODE='42501';END IF;
 RETURN NULL;
END $$;

CREATE FUNCTION kaname._authority_native_delete_batch_end_v4() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE batch_value jsonb;rows_value jsonb;
BEGIN
 IF TG_RELID<>'kaname.fga_outbox'::regclass OR TG_OP<>'INSERT' OR TG_LEVEL<>'STATEMENT'
  OR TG_WHEN<>'AFTER' OR TG_NAME<>'relation_fact_zz_native_batch' THEN
  RAISE EXCEPTION 'native batch closer trigger changed' USING ERRCODE='42501';END IF;
 batch_value:=kaname.authority_native_write_read_v4();
 IF batch_value IS NOT NULL THEN
  SELECT jsonb_agg(to_jsonb(j) ORDER BY j.id) INTO rows_value FROM journal_rows j;
  IF batch_value->>'phase'<>'policy-complete' OR batch_value->'rows' IS DISTINCT FROM rows_value THEN
   RAISE EXCEPTION 'native write policy or transition incomplete' USING ERRCODE='42501';END IF;
  UPDATE kaname.authority_forward_emit_anchor_v4 SET write_batch=jsonb_set(write_batch,'{phase}','"finished"'::jsonb)
  WHERE backend=pg_backend_pid() AND transaction_id=pg_current_xact_id() AND nonce=(batch_value->>'nonce')::uuid
   AND NOT finished AND write_required AND write_batch->>'phase'='policy-complete';
  IF NOT FOUND THEN RAISE EXCEPTION 'native write closer replay' USING ERRCODE='42501';END IF;
  RETURN NULL;
 END IF;
 batch_value:=kaname.authority_native_delete_batch_read_v4();
 IF batch_value IS NULL THEN RETURN NULL;END IF;
 SELECT jsonb_agg(to_jsonb(j) ORDER BY j.id) INTO rows_value FROM journal_rows j;
 IF batch_value->>'phase'='deleting' THEN
  -- Нулевой local approval не запускает fact DELETE и его callbacks.
  -- Уже удерживаемые invoker locks + exclusive admission закрывают изменение
  -- набора; closer лишь перепроверяет fresh отсутствие допустимых кандидатов.
  IF EXISTS(SELECT 1 FROM journal_rows j JOIN kaname.relation_fact f
   ON f.object_type=split_part(j.payload->>'object',':',1) AND f.object_id=split_part(j.payload->>'object',':',2)
    AND f.relation='editor' AND f.subject=j.payload->>'user'
   WHERE NOT EXISTS(SELECT 1 FROM kaname.access_binding_emitted_tuples et JOIN kaname.access_bindings ab ON ab.id=et.binding_id
    WHERE et.object=j.payload->>'object' AND et.relation=f.relation AND et.fga_user=f.subject AND ab.status='ACTIVE')
    AND NOT EXISTS(SELECT 1 FROM kaname.resource_registration_pointer rp WHERE rp.object_type=f.object_type
     AND rp.object_id=f.object_id AND rp.relation=f.relation AND rp.subject=f.subject AND rp.active)
    AND (f.source_version<=j.created_at OR EXISTS(SELECT 1 FROM kaname.resource_registration_pointer rp
     WHERE rp.object_type=f.object_type AND rp.object_id=f.object_id AND rp.relation=f.relation
      AND rp.subject=f.subject AND NOT rp.active))) THEN
   RAISE EXCEPTION 'native batch skipped eligible fact' USING ERRCODE='42501';END IF;
 END IF;
 IF batch_value->>'phase' NOT IN ('deleting','policy-complete') OR batch_value->'rows' IS DISTINCT FROM rows_value THEN
  RAISE EXCEPTION 'native batch policy or transition incomplete' USING ERRCODE='42501';END IF;
 UPDATE kaname.authority_forward_emit_anchor_v4 SET batch=jsonb_set(batch,'{phase}','"finished"'::jsonb)
 WHERE backend=pg_backend_pid() AND transaction_id=pg_current_xact_id() AND nonce=(batch_value->>'nonce')::uuid
 AND NOT finished AND batch->>'phase' IN ('deleting','policy-complete');
 IF NOT FOUND THEN RAISE EXCEPTION 'native batch closer replay' USING ERRCODE='42501';END IF;
 RETURN NULL;
END $$;

CREATE TRIGGER relation_fact_00_native_batch AFTER INSERT ON kaname.fga_outbox
 REFERENCING NEW TABLE AS journal_rows FOR EACH STATEMENT EXECUTE FUNCTION kaname._authority_native_delete_batch_begin_v4();
CREATE TRIGGER relation_fact_zz_native_batch AFTER INSERT ON kaname.fga_outbox
 REFERENCING NEW TABLE AS journal_rows FOR EACH STATEMENT EXECUTE FUNCTION kaname._authority_native_delete_batch_end_v4();

CREATE OR REPLACE FUNCTION kaname.relation_fact_from_journal() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE r record;batch_value jsonb;fact_value jsonb;approved jsonb[]:=ARRAY[]::jsonb[];
 expected_rows jsonb;actual_rows jsonb;v_object text;v_user text;v_id text;v_type text;
BEGIN
 -- Только explicit arm; старый direct prepare/claim по-прежнему generic.
 IF has_function_privilege(current_user,'kaname.authority_native_write_read_v4()','EXECUTE') THEN
  batch_value:=kaname.authority_native_write_read_v4();
 END IF;
 IF batch_value IS NOT NULL THEN
  IF batch_value->>'phase'<>'inserting' OR pg_trigger_depth()<>1
   OR replace(current_setting('search_path'),' ','')<>'pg_catalog,pg_temp' THEN
   RAISE EXCEPTION 'native write projection invocation changed' USING ERRCODE='42501';END IF;
  SELECT jsonb_agg(to_jsonb(j) ORDER BY j.id) INTO expected_rows FROM journal_rows j;
  IF expected_rows IS DISTINCT FROM batch_value->'rows' THEN
   RAISE EXCEPTION 'native write projection transition differs' USING ERRCODE='42501';END IF;
  -- Actual invoker UPSERT с исходными columns/defaults/conflict predicate.
  -- BEFORE/AFTER row guards выполняются executor для каждого actual факта.
  INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject,source_version,created_at,condition_name)
   SELECT split_part(j.payload->>'object',':',1),split_part(j.payload->>'object',':',2),'editor',j.payload->>'user',j.created_at,now(),''
   FROM journal_rows j ORDER BY j.payload->>'object' COLLATE "C",j.payload->>'user' COLLATE "C",j.id
   ON CONFLICT(object_type,object_id,relation,subject) DO UPDATE
    SET source_version=EXCLUDED.source_version,condition_name=EXCLUDED.condition_name
    WHERE kaname.relation_fact.source_version<EXCLUDED.source_version;
  RETURN NULL;
 END IF;
 -- Старый generic writer не обязан получать новый EXECUTE grant.
 IF has_function_privilege(current_user,'kaname.authority_native_delete_batch_read_v4()','EXECUTE') THEN
  batch_value:=kaname.authority_native_delete_batch_read_v4();
 END IF;
 IF batch_value IS NOT NULL THEN
  IF batch_value->>'phase'<>'deleting' THEN RAISE EXCEPTION 'native batch projection replay' USING ERRCODE='42501';END IF;
  SELECT jsonb_agg(to_jsonb(j) ORDER BY j.id) INTO expected_rows FROM journal_rows j;
  IF expected_rows IS DISTINCT FROM batch_value->'rows' THEN
   RAISE EXCEPTION 'native batch projection transition differs' USING ERRCODE='42501';END IF;
  -- Lock и следующий held read остаются РАЗНЫМИ invoker statements.
  FOR r IN SELECT j.* FROM journal_rows j ORDER BY j.payload->>'object' COLLATE "C",j.payload->>'user' COLLATE "C",j.id LOOP
   v_object:=r.payload->>'object';v_user:=r.payload->>'user';v_id:=split_part(v_object,':',2);v_type:=split_part(v_object,':',1);
   SELECT to_jsonb(f) INTO fact_value FROM kaname.relation_fact f
    WHERE object_type=v_type AND object_id=v_id AND relation='editor' AND subject=v_user FOR UPDATE;
   IF NOT FOUND THEN CONTINUE;END IF;
   IF EXISTS(SELECT 1 FROM kaname.access_binding_emitted_tuples et JOIN kaname.access_bindings ab ON ab.id=et.binding_id
     WHERE et.object=v_object AND et.relation='editor' AND et.fga_user=v_user AND ab.status='ACTIVE')
    OR EXISTS(SELECT 1 FROM kaname.resource_registration_pointer rp WHERE rp.object_type=v_type
     AND rp.object_id=v_id AND rp.relation='editor' AND rp.subject=v_user AND rp.active) THEN CONTINUE;END IF;
   IF (fact_value->>'source_version')::timestamptz<=r.created_at
    OR EXISTS(SELECT 1 FROM kaname.resource_registration_pointer rp WHERE rp.object_type=v_type
     AND rp.object_id=v_id AND rp.relation='editor' AND rp.subject=v_user AND NOT rp.active) THEN
    approved:=array_append(approved,fact_value);
   END IF;
  END LOOP;
  IF cardinality(approved)=0 THEN RETURN NULL;END IF;
  -- Один actual DELETE; guards/привилегии invoker сохранены, match полной
  -- locked row image исключает новый/изменённый факт и поздний широкий поиск.
  WITH deleted AS (
   DELETE FROM kaname.relation_fact f USING jsonb_array_elements(to_jsonb(approved)) a(image)
    WHERE f.object_type=a.image->>'object_type' AND f.object_id=a.image->>'object_id'
     AND f.relation=a.image->>'relation' AND f.subject=a.image->>'subject' AND to_jsonb(f)=a.image
    RETURNING to_jsonb(f) image)
   SELECT coalesce(jsonb_agg(image ORDER BY image::text COLLATE "C"),'[]'::jsonb) INTO actual_rows FROM deleted;
  SELECT jsonb_agg(image ORDER BY image::text COLLATE "C") INTO expected_rows FROM unnest(approved) image;
  IF actual_rows IS DISTINCT FROM expected_rows THEN
   RAISE EXCEPTION 'native batch actual deletion coverage differs' USING ERRCODE='42501';END IF;
  RETURN NULL;
 END IF;
 -- Прежняя generic свёртка и порядок остаются неизменны.
 FOR r IN SELECT j.event_type,j.payload,j.created_at FROM journal_rows j
  ORDER BY j.payload->>'object' COLLATE "C",j.payload->>'user' COLLATE "C",j.id LOOP
  PERFORM kaname.relation_fact_fold_row(r.event_type,r.payload,r.created_at);
 END LOOP;
 RETURN NULL;
END $$;

DO $$ DECLARE signature text;r record;BEGIN
 FOREACH signature IN ARRAY ARRAY['_authority_native_write_weights_v4(jsonb)','_authority_native_write_closure_v4()','authority_native_write_arm_v4(uuid)','authority_native_write_read_v4()','authority_native_delete_batch_read_v4()','_authority_native_delete_batch_begin_v4()','_authority_native_delete_batch_end_v4()','_authority_native_delete_batch_graph_v4()'] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM PUBLIC',signature);
  FOR r IN SELECT DISTINCT u.rolname FROM pg_catalog.pg_proc f CROSS JOIN LATERAL aclexplode(f.proacl) a
   JOIN pg_catalog.pg_roles u ON u.oid=a.grantee WHERE f.oid=to_regprocedure('kaname.'||signature) AND a.grantee<>f.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM %I',signature,r.rolname);
  END LOOP;
 END LOOP;
END $$;

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
 ('_authority_native_write_weights_v4(jsonb)','907111b7e806c46a660311a6a97fcc2ab2f86ea0430260fb501306f0e2ef522e',true,'s',true,'private'),
 ('_authority_native_write_closure_v4()','a6da6a23e1899bf23d71ba4c5969f66cdfe15a4038fb9a89223df803b74c0e14',true,'s',true,'private'),
 ('authority_native_write_arm_v4(uuid)','ec1e1600c2673f4d02947f7dca7b4a719abc794a91d0045bad38fc2c642e5638',true,'v',true,'export'),
 ('authority_native_write_read_v4()','f6a0242967e246de3f3d305655783afd29ed8bef4f4e8d95a8821c965aa33e9c',true,'v',true,'export'),
 ('authority_native_delete_batch_read_v4()','79e71a95aac2ded09885f8c65165ad8ac169ef3b7f09bbda82a11ce1baec80f9',true,'v',true,'export'),
 ('_authority_native_delete_batch_begin_v4()','d5f062e5543ded46945e843444184aed9f958ee776d63413095cc98c0ad5bd10',true,'v',true,'private'),
 ('_authority_native_delete_batch_end_v4()','3b8173b76b57f85ae4f73287e25b6e143a40c72a13d1423bf6ee218fa04d65fa',true,'v',true,'private'),
 ('_authority_native_delete_batch_graph_v4()','7b70a67aa67a72d2bf2a1136bf0477cda6239ef79b6ace61e4b2e6d8f3f841e6',true,'s',true,'private'),
 ('authority_native_delete_emit_v4(jsonb[])','3e36607d0fad78d6e89bf4b1d8212b939225c87f95bdfd0643020d5bb2933c1b',false,'v',true,'export'),
 ('authority_native_delete_prepare_v4(jsonb[])','b25ff1292dbced07ecffa2be2f736411cc61a3bf75dbcacd879ceeb01bc719cf',true,'v',true,'export'),
 ('authority_native_delete_stamp_v4(uuid,bigint,jsonb)','bed995919371e883bb0d88698a79f8d634c453068c4caab199d7a76cf026088c',true,'v',true,'export'),
 ('authority_forward_emit_v4(jsonb[])','d41825e5a57dbdc4f78b630f19877f54e94303e6fefc2b79b10e483fc6dd65e3',false,'v',true,'export'),
 ('authority_forward_prepare_v4(jsonb[])','8bfb60e9ff8c301d79c11215fdaac99c8788a78c920cae86182115bdc8e90d74',true,'v',true,'export'),
 ('authority_forward_claim_v4(uuid)','8a7c8ee8eae47a467c0d3370ef6185e93f3db6138aa14319563990fabd3b7be7',true,'v',true,'export'),
 ('authority_forward_finish_v4(uuid)','75683ffd52d23834a7e28814676b67a06d47cfa5a4fd2c2049d5f299f4c00199',true,'v',true,'export'),
 ('_authority_forward_context_v4()','67a9f0c6d896048f52b3eeb396250c7e33e16ab3170b874734154197d247dd5c',true,'v',true,'private'),
 ('_authority_forward_custody_v4()','a8007133abaae4f51966e623c6a515988e637ec2f0579838578602be2572801a',true,'v',true,'private'),
 ('_authority_forward_shape_v4()','ef281d009e6201f0c03e49cfc049b4950290fe1953bb05b3638536b45b0d66aa',true,'v',true,'private'),
 ('_authority_forward_program_v4(uuid)','d1100eb62bfc267ed7cc58d4d0cd0194f42b6285f8f465939381b60161607cca',true,'v',true,'private'),
 ('_authority_forward_row_v4(bigint,jsonb,boolean)','73e2e71c8a8eab73463ab36c58a5534333ba1ff88f308ac13d472e9be700888f',true,'v',true,'private'),
 ('_authority_forward_complete_v4(uuid)','06cfcd8f144243fc529aacba57f452b0913cc6d5b1ab6bf2daf7c4e6a9a38290',true,'v',true,'private'),
 ('_authority_forward_anchor_complete_v4()','0d9fdf6c02abe69e333b5584eee4628cafb7ec37849b7820e33aba4bea4396f1',true,'v',true,'private'),
 ('_authority_forward_storage_v4()','e8a9cd61f6ee6cc4fbde7361210cf493c8df166cdf3bfd8c49ed47190aa4ef0c',true,'s',true,'private'),
 ('_authority_group_add_program_v3()','e78556f1ccd014face052206b727651ce7e238bc9c3706f5a8d65f1f6559cce4',true,'v',true,'private'),
 ('authority_group_add_prepare_v3(jsonb,integer,integer)','ffe5527b2aed54dd69fa79b366c3717044cafdc98bed16f4c8ed9d39702d606e',true,'v',true,'export'),
 ('authority_group_add_finalize_v3(jsonb,integer,integer)','21d1ddc68b3e1cbf4bdbaabb6038c5bff865e7439420bd96c5e41590c91370dc',true,'v',true,'export'),
 ('_authority_group_add_row_v3(text,text,jsonb,jsonb)','a5973b00860baf37167efaf588cd3f3fe492248214708e3db6fa94ad7367590a',true,'v',true,'private'),
 ('_authority_group_add_statement_v3(text,text)','b2bad5333c59b9db498767c0a6546c089633f849799ab87efa991183ee799b11',true,'v',true,'private'),
 ('authority_group_add_fold_v3(text,jsonb,timestamptz)','cb582cd47c5e210fa7f4c4a4c0a211ba1b120b455ce9a868a453d05335a2d1ef',true,'v',true,'export'),
 ('authority_group_add_subject_id_v3()','bde80ceb4ed141b31a755dadb40e653acf46e9c89171b1bc93b2ac5f7916300e',true,'v',true,'export'),
 ('_authority_group_add_subject_v3(text,text,jsonb)','93f1e1147874032a6e7f4e1c08ad7651148e6ec5f25da7ffc2486d234ae14a8c',true,'v',true,'private'),
 ('_authority_group_add_complete_v3()','158eca8cc62068a844f08ce5f746ad909a504fb429567d11c30d6f496dcd17eb',true,'v',true,'private'),
 ('_authority_group_add_storage_v3()','123966ac8ae04e91375122a48bc6c07c8c48bda2791a763d779f00e506ff81fc',true,'s',true,'private'),
 ('relation_fact_fold_row(text,jsonb,timestamptz)','7f7b25757447007572b06ef18edbf60b3256b5ca218484ef98fefaf0f338e635',false,'v',false,'preserve'),
 ('authority_subject_change_id_guard_v2()','aa4bc39730f137bdf11491afaf41d9c8451c88e2cda40358fc0e33be2f29cb53',true,'v',true,'private'),
 ('authority_subject_change_applied_v2()','fa776df6d3b95dadb13fa1684424b2db105b21f5b8862bd045680fb8129d094e',true,'v',true,'private'),
 ('authority_subject_change_statement_guard_v2()','600129602604e3cac17840ff155738e5c886677cd8be781b62b9b29f2fe785b0',true,'v',true,'private'),
 ('relation_fact_from_journal()','604d827358eab2f756c0c53d9a65cfbaf31b3f5d19ff8adc6e3dab944e8fa70a',false,'v',false,'preserve'),
 ('authority_protocol_grant_runtime(regrole)','bae7413fe8dc3f578263bec41689d1aebc54051bec4826100b380e2f8c2a914a',false,'v',true,'preserve'),
 ('authority_binding_command_begin_v3(jsonb)','39696919bfed78731817c77a37920e661801933c5ac544bc26ea5603a7fa39b1',true,'v',true,'export'),
 ('authority_binding_command_end_v3(jsonb)','2c9ee43be689f773c543fc800645f2aae482ec02d392fd28937efa50558915b2',true,'v',true,'export'),
 ('authority_binding_command_audit_v3(jsonb)','93c1bfc6bd6b753868e68ff6e408089f701d189ed6e7c30a32c7998baade872f',true,'v',true,'export'),
 ('_authority_binding_mirror_policy_prepare_v3(jsonb)','62483d22c74491cc60dcbc011c5517f743b3a764dc91a48fa8628ce31bfadcd4',true,'v',true,'private'),
 ('authority_policy_changed()','d11c7b0992c5c8ddaa323fc03bfbc1822b52edbae5a181fa449589500e6440fe',true,'v',true,'preserve'),
 ('authority_audit_id_guard_v2()','a349a4a051b336afdec4cb5422edf5738fe4e354acec98163abc0d4a2c70d8f2',true,'v',true,'preserve'),
 ('authority_audit_applied_v2()','b43a45a017d3b646301d3b0eb746d46ae7ee7d3a0539b2c8b91600c5a4c697a3',true,'v',true,'preserve'),
 ('authority_audit_statement_guard_v2()','cc9fd152b1c8fa68a65eb6451baf977a12b0866cc52668254280265f10f9271c',true,'v',true,'preserve'),
 ('membership_mirror_from_user()','d763127654c0d5852aee7f86d8c5f5ea4fa89464c7f1e3c7df9efbace4e6c405',false,'v',false,'preserve'),
 ('_authority_resource_before_write_v3(jsonb,text,text,jsonb,jsonb)','10cfd5fcbe108b1f0b62f688d7ae80b72e34a536593fae3343c730cc0cb82da5',true,'v',true,'private'),
 ('_authority_resource_effect_applied_v2()','83057896665db04f47bf5837ca0f14cdbd83d187cba4d86c7aa40c11075d855a',true,'v',true,'private'),
 ('_authority_resource_write_v2(jsonb,text,text,jsonb,jsonb)','cdb26211660f6fc89ee193516c9bc7cfa3e3bdcd427d3cf71c17c4a047272c2f',true,'v',true,'private'),
 ('_authority_resource_side_v2(jsonb,text,text,text,jsonb)','09f8a713bf8e2a59ec0051910a49f5df93dec5bc5c776271c2f1a54dbb1eb8f1',true,'v',true,'private'),
 ('_authority_crud_anchor_capture_v3(jsonb,integer,integer)','2dee8b172ebd3b228b5c6cc4dec189feae30db2c1c9a4bc98752525025d823c7',true,'s',true,'private'),
 ('_authority_crud_authority_graph_v3(jsonb,jsonb,integer,integer)','3ce64fcc9997385efdac3a546dc44ab66e0b5022ec5d9cb5de8d5bfdcffaec9d',true,'s',true,'private'),
 ('_authority_crud_aux_capture_v3(jsonb,jsonb,integer,integer)','cbe93565f4de42904c6a0e2434db9a21ce0d528902d2a3908a2fec92cb821318',true,'s',true,'private'),
 ('_authority_crud_aux_write_v3()','5b549be379610152a2c2efc86836606fb82c298d885be0125cee3b535cf8cd32',true,'v',true,'private'),
 ('_authority_crud_aux_images_v3(jsonb,jsonb,jsonb,timestamptz)','f7cf945fa67c0bf19182121b6e31655f1939257dabac972618a15cd6fa9eda8b',true,'i',true,'private'),
 ('_authority_crud_aux_statement_v3()','8d2c6a5f46066b400d9c42c158a337eb784a405c895145beedc7205133be7bc6',true,'v',true,'private'),
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
 ('authority_resource_fold_body_v2(text,jsonb,timestamptz)','3eb8735862b7643f353c9e10312c2fe9ca251489f875c1faf30289f3d166b5d9',true,'v',true,'preserve'),
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
 ('authority_crud_sequence_guard_v3()','e7622cb38a1d1e6b81f01767a8071e9c46ab98e8f183aa2d05dde95c3740940b',true,'v',true,'private'),
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
 ('authority_protocol_statement_guard()','e188d77b0c72ec88024fb6ab264e2ae639679213ff727b5c61946dfde596bdad',true,'v',true,'preserve'),
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
 ('authority_binding_insert_stamp_v3(text)','0e37cf1836a1625f1c518c7c847cafe3da04ef9ef692db8c1c23fb27b40d1c71',true,'v',true,'export'),
 ('authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)','de942f0c6c21834ac9ecb177f4dce25e5c66c83101aaaf78bd23805ab04952a6',true,'v',true,'export'),
 ('_authority_binding_stage_snapshot_v3()','9e9d561435b0f86c51aec452283505184beee36e1dc02f4af708590955d2eebf',true,'v',true,'private'),
 ('authority_binding_stage_sequence_prepare_v3(text,text[],jsonb,integer,integer)','efdbe3e491e0c3bd8ade664a61d8e049094cc5b781f7fe14347a94e2dd5979e6',true,'v',true,'export'),
 ('authority_binding_stage_sequence_finalize_v3(text)','cd285782054ce7720b1072484e7b24758bcae7f8b7c7a117556b9836c1299a18',true,'v',true,'export'),
 ('_authority_audit_binding_store_v3()','c250435ecf40819b992439ff59b3435fe8a12e8f121677bbf17f8ed2b84d08ce',true,'v',true,'private'),
 ('_authority_binding_mirror_store_v3()','94398fb5e832f685ced7c84e6975e21e04729db15a39893977cce3dc32809b61',true,'v',true,'private'),
 ('_authority_binding_mirror_epoch_v3(text[],jsonb,timestamptz)','e6dd22497757ec3e7362e45c6d5f4a45cd5ecf5b43714b6849143e5da1bf134a',true,'v',true,'private'),
 ('_authority_binding_mirror_prepare_v3(jsonb,integer,integer)','8e4c9745f4df62265cb114849d1306493616a93049905a25f17c874dc0e35b9e',true,'v',true,'private'),
 ('_authority_binding_mirror_finalize_v3(text)','fe26d33c679cf15f72b04c243abff2c284fd2e5e35df1da58236cee3f826517e',true,'v',true,'private'),
 ('_authority_binding_mirror_before_write_v3(text,text,jsonb,jsonb)','91ee46ad24bb6267178100747185c18546bd1f01566e7b2780403f60c8995854',true,'v',true,'private'),
 ('authority_binding_epoch_lock(text[],jsonb)','621ce6546bd8a8fb0c64d73ba47b7094e8a8ddebcf0b76613d2896ebddb25d56',true,'v',true,'preserve'),
 ('_authority_binding_mirror_locality_v3(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb)','41c8b30fb6b70b3dee28f7a54fa1e692784b63df7ade0c0d1f0dfa955883fe9a',true,'i',true,'private'),
 ('_authority_binding_stage_source_v3(jsonb,oid,integer)','e3bd8688c1e38e2124e21c9f15bcbab1c2aad809352aa0002835d3e888d5088d',true,'v',true,'private'),
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
 ('authority_sequence_program_applied_v3()','008b3f5a88844e5708f4ec8c2c7cf7c105d2e1748f988b5945e65fa5800e9062',true,'v',true,'private'),
 ('authority_sequence_program_completion_v3()','055164a539031177a7605113484f5667702c9074b84d03ab1a827cd614b66e35',true,'v',true,'private'),
 ('_authority_sequence_expect_v3(text)','52e5bda884d0c1cec7bff0ae4843cd1490747432d1a44ee11a5648d6e905bcc2',true,'v',true,'private'),
 ('_authority_sequence_expected_v3()','e318cafb455438dd9a40e3c2cec7cc2d88daedf4307dd1e43248175005ab045b',true,'v',true,'private'),
 ('authority_sequence_expectation_complete_v3()','aef5c1e0bfa60d5587aa8c0f342b3f5df1166a1a699af56019f5bdf36e856c99',true,'v',true,'private'),
 ('resource_journal_emit()','76c8f397a387cb6699642e1d3aa56c2c61f371245eb28f56b14ed19c1d1faeba',false,'v',false,'preserve'),
 ('resource_journal_emit_member()','4dfca2c401a428e6b4ad984b99aae3a34404999ea36ed26b14c70b2ceb1d4053',false,'v',false,'preserve'),
 ('authority_sequence_origin_v3()','d1b7a54b0cf83d53d416b6cc2bbcb1c20e60d985356931a45a6804ebf2f27df3',true,'v',true,'private'),
 ('authority_prepared_journal_value_v3(jsonb,jsonb)','ec8e01085af732139c0478e82abd29817d25ca342afa4963d96491f8daca4017',true,'v',true,'export'),
 ('_authority_sequence_excluded_v3(oid)','eb4872a7f8c5bb7c40564e17fcc1928eac64bdbd8ac2e5609d261bd9ad36594b',true,'s',true,'private'),
 ('_authority_sequence_shape_v3()','614125faa823e6f14b0d2f58f2a6ed7ea9a5239febef2dd83b7ba4508f0f9014',true,'v',true,'private'),
 ('_authority_protocol_snapshot_v3()','f994c63975e86be78b2854a4f51aed55e615ad2c380b0f58fc1e0390662fc30a',true,'v',true,'private'),
 ('_authority_sequence_probe_v3()','2e2a3266993eadee820fba438960cde53cf25cd05a4e806661e8d62664f075c3',true,'v',true,'private'),
 ('_authority_sequence_header_v3()','375b51310e57a7016673ba26f5b9925d59e67a2599ba74fe9c11d3f5bf9c70f5',true,'v',true,'private'),
 ('_authority_sequence_publish_v3(jsonb)','013f8260baa0607516e57b791a92897d3d4bb143a401dd056166d1fbf70d3128',true,'v',true,'private'),
 ('_authority_sequence_store_v3()','adca627a6c7ce9b1ee755a231793134d5ebcc372f370c694cbac3f067fb471d2',true,'v',true,'private'),
 ('_authority_sequence_reserve_v3(text,jsonb,integer)','76e3ea26f6401f26ad25e168b0dc4399065648b354e7c8b96750a6d802128190',true,'v',true,'private'),
 ('_authority_sequence_select_v3(integer[],timestamptz)','7f9ce472e9d23f7a6182685661f2964bdc0266fefe1a59b9228d9908b171bb09',true,'v',true,'private'),
 ('_authority_sequence_claim_v3(text,jsonb,jsonb)','18cdb51c9e44fa944b355cadf1abcb291eba062ca09f3221118bcd60d736c740',true,'v',true,'private'),
 ('_authority_sequence_applied_v3(text,bigint,jsonb)','0a4c24ded6b6aad09fd077e4a1ad8d40dee440c4e27e44dc20e4300bfc0a5a7d',true,'v',true,'private'),
 ('_authority_sequence_complete_v3()','c9f728c4492acf65f92ea6a6f411b3af85e63e765c5226bbf3ea1e80fd9291d1',true,'v',true,'private'),
 ('authority_resource_finalize_v2(jsonb,integer,integer)','f68d6ef701f2e730fd10d2c65aec966d04aceaf54465ac87b684da8157985f0c',true,'v',true,'preserve'),
 ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','47aae35f146c1d05bf9f5f52f9f7b929d69d91f64b39844fd697530c467af440',true,'v',true,'preserve'),
 ('_authority_resource_object_program_v2(jsonb,timestamptz)','97f643954fbef4036c37240711c9ce9650045102c77bce1d5e8396d89a4c8464',true,'i',true,'preserve'),
 ('_authority_resource_object_sequence_prepare_v3(jsonb,integer)','bbf639e8b58fee3ee80ce322a7946cd5ae4a3f0a84804270117a369914fc5153',true,'v',true,'private'),
 ('_authority_resource_object_sequence_final_v3(jsonb,timestamptz)','48e8a4f9e9c57161fec84ede30f6a148a15a4cc5162d78dcfff4e048be037564',true,'v',true,'private'),
 ('_authority_resource_physical_relations_capture_v2(jsonb,integer,boolean)','e01481c788b47322941e6c6753d9d38e44e1bdcee973a8fb6292aed42d9ce54f',true,'v',true,'preserve'),
 ('_authority_resource_registration_sequence_prepare_v3(jsonb,integer,integer)','0d6ab18cc9cac1395df175c0c91912737bf8e78464d46da0c385e31aa36c9b66',true,'v',true,'private'),
 ('_authority_resource_registration_sequence_final_v3(jsonb,timestamptz)','ca262446dbab831c80c933c45b0095f12ceaa10367477a696266217b44736911',true,'v',true,'private'),
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
 ('_authority_resource_capture_index_v2(jsonb,integer)','988ed25715d6c9322bff7d8a6dc4d60b9d849a512d30ff9b70f8a1afbaa464f4',true,'i',true,'preserve'),
 ('_authority_resource_carrier_graph_v2(jsonb,text[],text[],text[],text[])','25cfe0b7f33582cfbee3399700901690952f97cff1e63d989ddde23176f42c80',true,'i',true,'preserve'),
 ('_authority_resource_carrier_scopes_v2(jsonb,jsonb)','0440ef56bc4069d6e1029e94dbab6acea6bddf7b5de88fc109f09f743599b60c',true,'i',true,'preserve'),
 ('_authority_resource_catalog_capture_wait_v2(jsonb,integer,integer,boolean)','c2dce8593b8f7616af573591ed0d439f822054f78f96de78ff8fc20d59efde18',true,'v',true,'preserve'),
 ('_authority_resource_catalog_wait_v2(jsonb,integer,integer)','6231367fd8a56cec22aed190ae2eef6dd8b3f93b2db1a0d8810ca6d9d5d53e97',true,'v',true,'preserve'),
 ('_authority_resource_contained_v2(text,text,jsonb,text)','e8cd715375fb48ff94738b78d82f00087fa548634ca3ebc43edd45dd54c8a758',true,'i',true,'preserve'),
 ('_authority_resource_coordinate_certificate_v2(jsonb,jsonb,text,jsonb,jsonb)','f463bd9d8f543624d5ca5d9f685bc2548b56410689a30470bcab07f0aa0d6790',true,'i',true,'preserve'),
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
 ('_authority_resource_special_member_core_v2(jsonb,jsonb,text,jsonb,jsonb,jsonb)','24e7fbc54d15adea39c37df0bff9d333725a2a17911080d1698329cabc603754',true,'i',true,'private'),
 ('_authority_resource_special_member_v2(jsonb,jsonb,text,jsonb,jsonb,jsonb)','9415be5436a7ed74e97131d996f346df3f1b02d23c7f5b108fa7788629a0c6ed',true,'i',true,'preserve'),
 ('_authority_resource_subject_change_wait_v2(integer,integer)','bb5f61c161012d21fe2480ffbdc61fc8095ceb1d9d265a13b26530b22b568632',true,'v',true,'preserve'),
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
 ('authority_binding_epoch_changed()','38ea9bd9f48943d6d093e4218fbc0e5a1184459719b89743e20cfb7089c7d614',true,'v',true,'preserve'),
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
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname._authority_binding_mirror_locality_v3(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb)'::regprocedure
   AND p.prokind='f' AND p.prorettype='boolean'::regtype AND NOT p.proretset AND NOT p.proisstrict
   AND NOT p.proleakproof AND p.proparallel='u' AND p.pronargs=6 AND p.pronargdefaults=0
   AND p.proargmodes IS NULL AND p.provariadic=0 AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')) THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM (VALUES
 ('_authority_audit_binding_store_v3()','jsonb',0,false), ('_authority_binding_mirror_store_v3()','jsonb',0,false), ('_authority_binding_mirror_epoch_v3(text[],jsonb,timestamptz)','void',3,false), ('_authority_binding_mirror_prepare_v3(jsonb,integer,integer)','record',3,true), ('_authority_binding_mirror_finalize_v3(text)','void',1,false), ('_authority_binding_mirror_before_write_v3(text,text,jsonb,jsonb)','boolean',4,false)
 ) abi_expected(signature,result_type,nargs,returns_set) LEFT JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||abi_expected.signature)
 WHERE p.oid IS NULL OR p.prokind<>'f' OR p.prorettype<>abi_expected.result_type::regtype OR p.proretset<>abi_expected.returns_set
 OR p.proisstrict OR p.proleakproof OR p.proparallel<>'u' OR p.pronargs<>abi_expected.nargs OR p.pronargdefaults<>0 OR p.provariadic<>0
 OR p.prolang<>(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
 OR CASE WHEN abi_expected.returns_set THEN p.proargmodes IS DISTINCT FROM ARRAY['i','i','i','t','t']::"char"[]
  OR p.proallargtypes IS DISTINCT FROM ARRAY['jsonb'::regtype,'integer'::regtype,'integer'::regtype,'integer'::regtype,'integer'::regtype]::oid[]
  OR p.proargnames IS DISTINCT FROM ARRAY['p_snapshot','p_rows','p_reads','logical_rows','logical_reads']::text[]
 ELSE p.proargmodes IS NOT NULL OR p.proallargtypes IS NOT NULL END) THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM (VALUES
 ('authority_binding_command_begin_v3(jsonb)','boolean','p_command'),
 ('authority_binding_command_end_v3(jsonb)','void','p_command'),
 ('authority_binding_command_audit_v3(jsonb)','boolean','p_command'),
 ('_authority_binding_mirror_policy_prepare_v3(jsonb)','void','p_snapshot')
 ) e(signature,result_type,argname) LEFT JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||e.signature)
 WHERE p.oid IS NULL OR p.prokind<>'f' OR p.prorettype<>e.result_type::regtype OR p.proretset
 OR p.proisstrict OR p.proleakproof OR p.proparallel<>'u' OR p.pronargs<>1 OR p.pronargdefaults<>0
 OR p.provariadic<>0 OR p.proargmodes IS NOT NULL OR p.proallargtypes IS NOT NULL
 OR p.proargnames IS DISTINCT FROM ARRAY[e.argname]::text[] OR p.proargtypes[0]<>'jsonb'::regtype
 OR p.prolang<>(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid='kaname._authority_resource_special_member_core_v2(jsonb,jsonb,text,jsonb,jsonb,jsonb)'::regprocedure
  AND p.prorettype='pg_catalog.bool'::regtype AND p.pronargs=6 AND p.proargtypes='3802 3802 25 3802 3802 3802'::oidvector
  AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
  AND NOT p.proretset AND NOT p.proisstrict AND p.prokind='f' AND p.pronargdefaults=0 AND p.provariadic=0
  AND p.proallargtypes IS NULL AND p.proargmodes IS NULL) THEN RETURN false;END IF;
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
 ('resource_registration_scope','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('resource_registration_scope','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('resource_registration_scope','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('resource_registration_scope','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
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
 IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname.authority_binding_epoch_changed()'::regprocedure)<>96 THEN RETURN false;END IF;
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
 IF EXISTS(SELECT 1 FROM (VALUES
  ('authority_native_delete_emit_v4(jsonb[])','void',1,ARRAY['p_payloads']),
  ('authority_native_delete_prepare_v4(jsonb[])','uuid',1,ARRAY['p_payloads']),
  ('authority_native_delete_stamp_v4(uuid,bigint,jsonb)','timestamptz',3,ARRAY['p_nonce','p_id','p_payload'])
 ) e(signature,result_type,nargs,names) LEFT JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||e.signature)
 WHERE p.oid IS NULL OR p.prokind<>'f' OR p.prorettype<>e.result_type::regtype OR p.proretset
 OR p.proisstrict OR p.proleakproof OR p.proparallel<>'u' OR p.pronargs<>e.nargs OR p.pronargdefaults<>0 OR p.provariadic<>0
 OR p.proargnames IS DISTINCT FROM e.names OR p.proargmodes IS NOT NULL OR p.proallargtypes IS NOT NULL
 OR p.prolang<>(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')) THEN RETURN false;END IF;
 RETURN kaname._authority_group_add_storage_v3() AND kaname._authority_forward_storage_v4();
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
 ('_authority_crud_storage_v3()','7b17d2f654879c1df3ccca4e3c55cc02f5b17522675114e76dbe1bf122de8937',true),
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
 ('authority_protocol_attestation()','130a504f7da2b6780cd4e91a2c7103f9fabe765541f0f2611f900ce679ddd502',true),
 ('authority_protocol_statement_guard()','e188d77b0c72ec88024fb6ab264e2ae639679213ff727b5c61946dfde596bdad',true),
 ('authority_protocol_row_guard()','0207ee81f4012cabec1fccbf6e816763b4889d064bf896e7455be9a35e5417a1',true),
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
 IF NOT kaname._authority_full_contract_storage_v3() THEN RAISE EXCEPTION 'binding runtime grant closure incomplete' USING ERRCODE='55000';END IF;
 PERFORM kaname._authority_protocol_grant_runtime_generation1(p_runtime);
 SELECT rolname INTO STRICT runtime_name FROM pg_catalog.pg_roles WHERE oid=p_runtime;
 FOREACH signature IN ARRAY ARRAY[
  'authority_native_write_arm_v4(uuid)','authority_native_write_read_v4()',
  'authority_native_delete_batch_read_v4()',
  'authority_native_delete_emit_v4(jsonb[])',
  'authority_native_delete_prepare_v4(jsonb[])',
  'authority_native_delete_stamp_v4(uuid,bigint,jsonb)',
  'authority_forward_emit_v4(jsonb[])',
  'authority_forward_prepare_v4(jsonb[])',
  'authority_forward_claim_v4(uuid)',
  'authority_forward_finish_v4(uuid)',
  'authority_group_add_prepare_v3(jsonb,integer,integer)',
  'authority_group_add_finalize_v3(jsonb,integer,integer)',
  'authority_group_add_fold_v3(text,jsonb,timestamptz)',
  'authority_group_add_subject_id_v3()',
  'authority_resource_crud_capture_v3(jsonb,integer,integer)',
  'authority_resource_crud_body_values_v3()',
  'authority_resource_crud_step_v3(text,jsonb)',
  'authority_resource_crud_lock_held_v3(text)',
  'authority_resource_crud_journal_value_v3(jsonb,jsonb)',
  'authority_binding_command_begin_v3(jsonb)',
  'authority_binding_command_end_v3(jsonb)',
  'authority_binding_command_audit_v3(jsonb)',
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
 FOREACH signature IN ARRAY ARRAY['_authority_protocol_snapshot_v3()','_authority_sequence_probe_v3()','_authority_sequence_shape_v3()','_authority_sequence_publish_v3(jsonb)','_authority_sequence_header_v3()','_authority_resource_before_write_v3(jsonb,text,text,jsonb,jsonb)','_authority_crud_anchor_capture_v3(jsonb,integer,integer)','_authority_crud_authority_graph_v3(jsonb,jsonb,integer,integer)','_authority_crud_aux_capture_v3(jsonb,jsonb,integer,integer)','_authority_crud_aux_write_v3()','_authority_crud_aux_images_v3(jsonb,jsonb,jsonb,timestamptz)','_authority_crud_aux_statement_v3()','authority_resource_crud_capture_v3(jsonb,integer,integer)','_authority_crud_merge_tables_v3(jsonb,jsonb)','_authority_crud_capture_v3(jsonb,integer,integer)','_authority_crud_cascade_capture_v3(jsonb,integer,integer)','authority_resource_crud_body_values_v3()','_authority_crud_step_complete_v3(jsonb,integer)','authority_resource_crud_step_v3(text,jsonb)','authority_resource_crud_lock_held_v3(text)','_authority_crud_require_completion_v3(jsonb)','_authority_crud_command_v3(text,jsonb)','_authority_crud_structural_v3(text,text,text,text)','_authority_crud_command_plan_v3(jsonb,jsonb)','_authority_crud_image_v3(integer,text,text,jsonb,jsonb,boolean)','_authority_crud_domain_images_v3(jsonb,jsonb,jsonb,timestamptz)','_authority_crud_intent_v3(jsonb)','_authority_crud_manifest_domain_v3(jsonb)','_authority_crud_fga_rows_v3(jsonb,text,jsonb,integer,timestamptz)','authority_crud_fga_id_guard_v3()','authority_crud_fga_id_applied_v3()','_authority_crud_fold_capture_v3(jsonb,integer,integer)','_authority_crud_fold_images_v3(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','_authority_crud_graph_index_v3(jsonb,jsonb,jsonb)','_authority_crud_journal_capture_v3(jsonb,jsonb,integer,integer)','authority_resource_crud_journal_value_v3(jsonb,jsonb)','authority_crud_journal_applied_v3()','_authority_crud_journal_plan_v3(jsonb,jsonb,jsonb)','_authority_crud_journal_rows_v3(jsonb,jsonb,timestamptz)','_authority_crud_unique_key_v3(text,jsonb)','authority_crud_unique_guard_v3()','_authority_crud_sequence_wait_v3(text,integer,integer)','authority_crud_sequence_guard_v3()','_authority_crud_key_maximum_v3(jsonb,jsonb,jsonb,jsonb,timestamptz)','_authority_crud_lock_rows_v3(jsonb)','_authority_crud_lock_plan_v3(jsonb,jsonb,jsonb,timestamptz)','_authority_crud_manifest_images_v3(jsonb,jsonb,jsonb,jsonb)','_authority_resource_crud_materialize_v3(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','_authority_crud_maximum_v3(jsonb,jsonb)','_authority_crud_pack_v3(jsonb,jsonb,jsonb)','_authority_crud_physical_v3(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','_authority_resource_crud_prepare_v3(jsonb,integer,integer)','_authority_crud_relation_wait_v3(jsonb,jsonb,jsonb,integer)','_authority_crud_reserve_v3(jsonb,jsonb,jsonb,integer,integer)','_authority_crud_scope_capture_v3(jsonb,integer,integer)','_authority_resource_crud_store_v3(jsonb)','_authority_crud_tuple_wait_v3(text,jsonb,boolean,integer,integer)','_authority_crud_unique_wait_v3(text,jsonb,integer,integer)','_authority_crud_json_keys_v3(jsonb)','_authority_crud_write_metadata_v3(jsonb,jsonb,jsonb)','_authority_binding_scope_tier_v3(text,jsonb,jsonb)','_authority_binding_journal_v3(text,text,jsonb,jsonb,jsonb,integer)','authority_binding_sequence_prepare_v3(text,jsonb)','authority_binding_sequence_finalize_v3()','authority_binding_insert_stamp_v3(text)','authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)','_authority_binding_stage_snapshot_v3()','authority_binding_stage_sequence_prepare_v3(text,text[],jsonb,integer,integer)','authority_binding_stage_sequence_finalize_v3(text)','_authority_audit_binding_store_v3()','_authority_binding_mirror_store_v3()','_authority_binding_mirror_epoch_v3(text[],jsonb,timestamptz)','_authority_binding_mirror_prepare_v3(jsonb,integer,integer)','_authority_binding_mirror_finalize_v3(text)','_authority_binding_mirror_before_write_v3(text,text,jsonb,jsonb)','_authority_binding_mirror_locality_v3(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb)','_authority_binding_stage_source_v3(jsonb,oid,integer)','_authority_binding_stage_coordinates_v3(jsonb,text[],boolean,oid,integer,integer)','authority_binding_withdrawal_sequence_prepare_v3(text,text,text,integer,integer)','authority_binding_withdrawal_sequence_finalize_v3()','authority_cluster_admin_preflight_v4(text,text,text)','_authority_metadata_preflight_body_v4(text,text,boolean,text)','_authority_sequence_freeze_v3(jsonb)','_authority_sequence_bind_v3(jsonb,timestamptz)','_authority_sequence_default_v3(text)','authority_resource_journal_id_v3()','authority_fga_outbox_id_v3()','authority_sequence_program_applied_v3()','authority_sequence_program_completion_v3()','_authority_sequence_expect_v3(text)','_authority_sequence_expected_v3()','authority_sequence_expectation_complete_v3()','authority_sequence_origin_v3()','authority_prepared_journal_value_v3(jsonb,jsonb)','_authority_sequence_excluded_v3(oid)','_authority_sequence_store_v3()','_authority_sequence_reserve_v3(text,jsonb,integer)','_authority_sequence_select_v3(integer[],timestamptz)','_authority_sequence_claim_v3(text,jsonb,jsonb)','_authority_sequence_applied_v3(text,bigint,jsonb)','_authority_sequence_complete_v3()','_authority_resource_object_sequence_prepare_v3(jsonb,integer)','_authority_resource_object_sequence_final_v3(jsonb,timestamptz)','_authority_resource_registration_sequence_prepare_v3(jsonb,integer,integer)','_authority_resource_registration_sequence_final_v3(jsonb,timestamptz)','authority_role_sequence_prepare_v3(jsonb,integer,integer)','authority_role_sequence_finalize_v3()','authority_role_sequence_stamp_v3(jsonb)','_authority_sa_state_preflight_body_v4(text,boolean,text)','_authority_scalar_journal_v3(text,text,jsonb,jsonb)','authority_metadata_preflight_v4(text,text,boolean,text,jsonb)','authority_sa_state_preflight_v4(text,boolean,text)','authority_scalar_sequence_finalize_v3()','authority_crud_storage_v3()','_authority_crud_storage_v3()'] LOOP
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
CREATE TRIGGER binding_epoch_insert AFTER INSERT ON kaname.resource_registration_scope REFERENCING NEW TABLE AS new_epoch_rows FOR EACH STATEMENT EXECUTE FUNCTION kaname.authority_binding_epoch_changed();
CREATE TRIGGER binding_epoch_update AFTER UPDATE ON kaname.resource_registration_scope REFERENCING OLD TABLE AS old_epoch_rows NEW TABLE AS new_epoch_rows FOR EACH STATEMENT EXECUTE FUNCTION kaname.authority_binding_epoch_changed();
CREATE TRIGGER binding_epoch_delete AFTER DELETE ON kaname.resource_registration_scope REFERENCING OLD TABLE AS old_epoch_rows FOR EACH STATEMENT EXECUTE FUNCTION kaname.authority_binding_epoch_changed();
CREATE TRIGGER binding_epoch_truncate AFTER TRUNCATE ON kaname.resource_registration_scope FOR EACH STATEMENT EXECUTE FUNCTION kaname.authority_binding_epoch_changed();


-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_resource_effect_applied_v2() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb; old_image jsonb; new_image jsonb; matched jsonb;
 ordinal integer;v_old_image jsonb;v_new_image jsonb;
BEGIN
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NULL THEN
  IF TG_TABLE_NAME NOT IN ('access_binding_target_members','access_binding_emitted_tuples','fga_outbox','relation_fact')
   OR kaname._authority_binding_mirror_store_v3() IS NULL THEN RETURN NULL;END IF;
  IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' THEN RAISE EXCEPTION 'binding mirror applied context invalid' USING ERRCODE='42501';END IF;
  IF TG_OP<>'INSERT' THEN v_old_image:=to_jsonb(OLD);END IF;
  IF TG_OP<>'DELETE' THEN v_new_image:=to_jsonb(NEW);END IF;
  IF TG_TABLE_NAME='fga_outbox' THEN v_new_image:=v_new_image-'id';END IF;
  SELECT i.image_no INTO ordinal FROM pg_temp.kaname_binding_mirror_images i
   WHERE i.table_name=TG_TABLE_NAME AND i.operation=TG_OP AND i.attempted AND NOT i.consumed
   AND i.old_image IS NOT DISTINCT FROM v_old_image AND i.new_image IS NOT DISTINCT FROM v_new_image
   ORDER BY i.command_no,i.image_no LIMIT 1;
  IF ordinal IS NULL OR NOT (SELECT i.required FROM pg_temp.kaname_binding_mirror_images i WHERE i.image_no=ordinal) THEN
   RAISE EXCEPTION 'binding mirror unprepared actual effect' USING ERRCODE='42501';END IF;
  UPDATE pg_temp.kaname_binding_mirror_images i SET consumed=true WHERE i.image_no=ordinal;
  RETURN NULL;
 END IF;
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP NOT IN ('INSERT','UPDATE','DELETE') THEN
  RAISE EXCEPTION 'resource applied-effect trigger context invalid' USING ERRCODE='42501';
 END IF;
 IF TG_OP<>'INSERT' THEN old_image:=to_jsonb(OLD); END IF;
 IF TG_OP<>'DELETE' THEN new_image:=to_jsonb(NEW); END IF;
 matched:=kaname._authority_resource_write_v2(manifest,TG_TABLE_NAME,TG_OP,old_image,new_image);
 IF jsonb_typeof(matched->'required') IS DISTINCT FROM 'boolean' THEN
  RAISE EXCEPTION 'resource effect obligation is missing' USING ERRCODE='42501';
 END IF;
 IF matched->>'required'='false' THEN
  -- Разрешение BEFORE на попытку INSERT не разрешает persisted INSERT:
  -- ожидаемый ON CONFLICT/DO NOTHING должен остаться без AFTER ROW эффекта.
  RAISE EXCEPTION 'resource attempted-only image persisted' USING ERRCODE='42501';
 END IF;
 IF TG_TABLE_NAME='fga_outbox' AND TG_OP='INSERT' THEN
  -- BEFORE guard уже одноразово выбрал разрешение без surrogate id. Из
  -- одинаковых разрешений учитывается лишь действительно потреблённое.
  SELECT e.ordinality::integer INTO ordinal
   FROM pg_temp.kaname_authority_resource_manifest r
   CROSS JOIN LATERAL jsonb_array_elements(r.writes) WITH ORDINALITY e(value,ordinality)
   WHERE e.value=matched AND e.ordinality::integer=ANY(r.consumed_outbox_writes)
    AND NOT e.ordinality::integer=ANY(r.consumed_required_writes)
   ORDER BY e.ordinality LIMIT 1;
 ELSE
  -- Повтор одного exact mandatory эффекта имеет отдельный ordinal.
  -- Удалять multiplicity нельзя: DELETE/recreate/DELETE обязан завершить
  -- оба удаления, а третий лишний actual эффект должен быть отвергнут.
  SELECT e.ordinality::integer INTO ordinal
   FROM pg_temp.kaname_authority_resource_manifest r
   CROSS JOIN LATERAL jsonb_array_elements(r.writes) WITH ORDINALITY e(value,ordinality)
   WHERE e.value=matched AND NOT e.ordinality::integer=ANY(r.consumed_required_writes)
   ORDER BY e.ordinality LIMIT 1;
 END IF;
 IF ordinal IS NULL THEN RAISE EXCEPTION 'resource applied effect was not prepared' USING ERRCODE='42501'; END IF;
 PERFORM kaname._authority_resource_consume_required_v2(ordinal);
 RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_policy_changed() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE group_program jsonb;keys text[]; k text; moved boolean:=false; manifest jsonb; image jsonb; metadata jsonb; resource_keys text[]; resource_roles text[];
BEGIN
 group_program:=kaname._authority_group_add_program_v3();
 IF group_program IS NOT NULL THEN
  -- Исходный FGA policy trigger остаётся no-op: actual AFTER STATEMENT
  -- приходит до relation_fact relay. Проверяем только уже consumed frozen
  -- строки; policy revisions меняются позднее от реальных fact transitions.
  IF TG_TABLE_NAME='fga_outbox' AND TG_OP='INSERT' THEN
   FOR image IN SELECT to_jsonb(n) FROM new_policy_rows n LOOP
    IF NOT EXISTS(SELECT 1 FROM pg_temp.kaname_authority_sequence_effects e
     WHERE e.nonce=(group_program->>'nonce')::uuid AND e.table_name='fga_outbox'
      AND e.selected AND e.claimed AND e.consumed AND e.reserved_id=(image->>'id')::bigint
      AND e.row_value=image-'id') THEN
     RAISE EXCEPTION 'group addition FGA policy transition image differs' USING ERRCODE='42501';END IF;
   END LOOP;
   RETURN NULL;
  END IF;
  IF TG_TABLE_NAME NOT IN ('group_members','relation_fact') OR TG_OP NOT IN ('INSERT','UPDATE') THEN
   RAISE EXCEPTION 'group addition policy transition outside command' USING ERRCODE='42501';END IF;
  keys:=ARRAY[]::text[];
  FOR image IN SELECT to_jsonb(n) FROM new_policy_rows n LOOP
   IF (TG_TABLE_NAME='group_members' AND image IS DISTINCT FROM
     (group_program#>'{frozen,member_template}')||jsonb_build_object('added_at',(group_program->>'decision_at')::timestamptz))
   OR (TG_TABLE_NAME='relation_fact' AND image IS DISTINCT FROM group_program#>'{frozen,fact_final}') THEN
    RAISE EXCEPTION 'group addition policy transition image differs' USING ERRCODE='42501';END IF;
   keys:=ARRAY(SELECT jsonb_array_elements_text(group_program#>ARRAY['frozen',CASE TG_TABLE_NAME WHEN 'group_members' THEN 'member_keys' ELSE 'fact_keys' END]));
  END LOOP;
  FOR k IN SELECT DISTINCT x COLLATE "C" FROM unnest(keys) x ORDER BY 1 LOOP
   -- FOR UPDATE уже выполнен compiler: здесь только прежний revision+1.
   UPDATE kaname.authority_policy_epoch SET revision=revision+1 WHERE key=k;
   IF NOT FOUND THEN RAISE EXCEPTION 'group addition prepared policy key absent' USING ERRCODE='42501';END IF;
  END LOOP;
  RETURN NULL;
 END IF;
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NOT NULL THEN
  IF TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'resource truncate denied' USING ERRCODE='42501'; END IF;
  resource_keys:=ARRAY[]::text[]; resource_roles:=ARRAY[]::text[];
  IF TG_OP<>'INSERT' THEN
   FOR image IN SELECT to_jsonb(o) FROM old_policy_rows o LOOP
    metadata:=kaname._authority_resource_side_v2(manifest,TG_TABLE_NAME,TG_OP,'old',image);
    resource_keys:=resource_keys||kaname._authority_resource_key_array_v2(metadata->'epoch_write_keys',false);
    resource_roles:=resource_roles||kaname._authority_resource_key_array_v2(metadata->'deferred_carrier_roles');
    SELECT coalesce(array_agg(DISTINCT x),ARRAY[]::text[]) INTO resource_keys FROM unnest(resource_keys) x;
    SELECT coalesce(array_agg(DISTINCT x),ARRAY[]::text[]) INTO resource_roles FROM unnest(resource_roles) x;
   END LOOP;
  END IF;
  IF TG_OP<>'DELETE' THEN
   FOR image IN SELECT to_jsonb(n) FROM new_policy_rows n LOOP
    metadata:=kaname._authority_resource_side_v2(manifest,TG_TABLE_NAME,TG_OP,'new',image);
    resource_keys:=resource_keys||kaname._authority_resource_key_array_v2(metadata->'epoch_write_keys',false);
    resource_roles:=resource_roles||kaname._authority_resource_key_array_v2(metadata->'deferred_carrier_roles');
    SELECT coalesce(array_agg(DISTINCT x),ARRAY[]::text[]) INTO resource_keys FROM unnest(resource_keys) x;
    SELECT coalesce(array_agg(DISTINCT x),ARRAY[]::text[]) INTO resource_roles FROM unnest(resource_roles) x;
   END LOOP;
  END IF;
  FOR k IN SELECT DISTINCT x COLLATE "C" FROM unnest(resource_keys) x ORDER BY 1 LOOP
   IF NOT ((manifest->'epoch_write_keys') ? k) THEN
    RAISE EXCEPTION 'resource epoch write was not prepared' USING ERRCODE='42501';
   END IF;
   PERFORM kaname._authority_resource_preheld_key_v2(1262569296,k,true);
   -- Ни INSERT, ни повторного FOR UPDATE после final clock.
   UPDATE kaname.authority_policy_epoch SET revision=revision+1 WHERE key=k;
   IF NOT FOUND THEN RAISE EXCEPTION 'resource prepared epoch missing' USING ERRCODE='40001'; END IF;
  END LOOP;
  FOR k IN SELECT DISTINCT x COLLATE "C" FROM unnest(resource_roles) x ORDER BY 1 LOOP
   -- Только queued carrier metadata; actual bump сохраняется в deferred flush.
   PERFORM kaname._authority_resource_preheld_key_v2(1262569296,'carrier_latch:role:'||k,false);
   PERFORM kaname._authority_resource_preheld_key_v2(1262569296,'carriers:role:'||k,true);
   INSERT INTO kaname.authority_policy_carrier_pending(transaction_id,backend_pid,role_id)
   VALUES(pg_current_xact_id(),pg_backend_pid(),k) ON CONFLICT DO NOTHING;
  END LOOP;
  RETURN NULL;
 END IF;
 IF TG_TABLE_NAME='relation_fact' AND kaname._authority_binding_mirror_store_v3() IS NOT NULL THEN
  keys:=ARRAY[]::text[];
  IF TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'binding mirror policy truncate denied' USING ERRCODE='42501';END IF;
  IF TG_OP<>'INSERT' THEN
   FOR image IN SELECT to_jsonb(o) FROM old_policy_rows o LOOP
    SELECT i.epoch_keys INTO metadata FROM pg_temp.kaname_binding_mirror_images i
     WHERE i.table_name='relation_fact' AND i.operation=TG_OP AND i.old_image=image AND i.consumed LIMIT 1;
    IF metadata IS NULL THEN RAISE EXCEPTION 'binding mirror policy OLD absent' USING ERRCODE='42501';END IF;
    keys:=keys||ARRAY(SELECT jsonb_array_elements_text(metadata));
   END LOOP;
  END IF;
  IF TG_OP<>'DELETE' THEN
   FOR image IN SELECT to_jsonb(n) FROM new_policy_rows n LOOP
    SELECT i.epoch_keys INTO metadata FROM pg_temp.kaname_binding_mirror_images i
     WHERE i.table_name='relation_fact' AND i.operation=TG_OP AND i.new_image=image AND i.consumed LIMIT 1;
    IF metadata IS NULL THEN RAISE EXCEPTION 'binding mirror policy NEW absent' USING ERRCODE='42501';END IF;
    keys:=keys||ARRAY(SELECT jsonb_array_elements_text(metadata));
   END LOOP;
  END IF;
  FOR k IN SELECT DISTINCT x COLLATE "C" FROM unnest(keys) x ORDER BY 1 LOOP
   IF NOT EXISTS(SELECT 1 FROM pg_temp.kaname_binding_mirror_program p WHERE p.policy_keys ? k AND p.final_clock IS NOT NULL) THEN
    RAISE EXCEPTION 'binding mirror policy key not preheld' USING ERRCODE='42501';END IF;
   UPDATE kaname.authority_policy_epoch SET revision=revision+1 WHERE key=k;
   IF NOT FOUND THEN RAISE EXCEPTION 'binding mirror policy epoch absent' USING ERRCODE='40001';END IF;
  END LOOP;
  RETURN NULL;
 END IF;
 -- WRITE-only obligations: actual empty UPDATE, then exact all-new INSERT.
 IF TG_TABLE_NAME='relation_fact' AND TG_OP IN ('INSERT','UPDATE') THEN
  metadata:=kaname.authority_native_write_read_v4();
  IF metadata IS NOT NULL THEN
   IF TG_RELID<>'kaname.relation_fact'::regclass OR TG_LEVEL<>'STATEMENT' OR TG_WHEN<>'AFTER' OR pg_trigger_depth()<>2 THEN
    RAISE EXCEPTION 'native write policy invocation changed' USING ERRCODE='42501';END IF;
   IF TG_OP='UPDATE' THEN
    IF metadata->>'phase'<>'inserting' OR EXISTS(SELECT 1 FROM old_policy_rows) OR EXISTS(SELECT 1 FROM new_policy_rows) THEN
     RAISE EXCEPTION 'native write conflict UPDATE was not empty' USING ERRCODE='42501';END IF;
    UPDATE kaname.authority_forward_emit_anchor_v4 SET write_batch=jsonb_set(write_batch,'{phase}','"empty-update"'::jsonb)
    WHERE backend=pg_backend_pid() AND transaction_id=pg_current_xact_id() AND nonce=(metadata->>'nonce')::uuid
     AND NOT finished AND write_batch->>'phase'='inserting';
    IF NOT FOUND THEN RAISE EXCEPTION 'native write empty UPDATE replay' USING ERRCODE='42501';END IF;
    RETURN NULL;
   END IF;
   IF metadata->>'phase'<>'empty-update'
    OR (SELECT coalesce(jsonb_agg(to_jsonb(n) ORDER BY to_jsonb(n)::text COLLATE "C"),'[]'::jsonb) FROM new_policy_rows n)
     IS DISTINCT FROM (SELECT jsonb_agg(j ORDER BY j::text COLLATE "C") FROM jsonb_array_elements(metadata->'facts') j) THEN
    RAISE EXCEPTION 'native write actual NEW coverage changed' USING ERRCODE='42501';END IF;
   -- Пересчёт fresh ownership после waits, без использования stale key proof.
   IF kaname._authority_native_write_weights_v4((SELECT jsonb_agg(to_jsonb(n)) FROM new_policy_rows n))
     IS DISTINCT FROM metadata->'weights'
    OR (SELECT coalesce(jsonb_object_agg(w.key,to_jsonb(e)),'{}'::jsonb)
      FROM (SELECT key FROM jsonb_each_text(metadata->'weights') UNION ALL SELECT '*') w LEFT JOIN kaname.authority_policy_epoch e ON e.key=w.key)
     IS DISTINCT FROM metadata->'epochs' THEN
    RAISE EXCEPTION 'native write policy dependencies changed after arm' USING ERRCODE='42501';END IF;
   PERFORM key FROM kaname.authority_policy_epoch WHERE key='*' FOR SHARE;
   INSERT INTO kaname.authority_policy_epoch(key,revision)
    SELECT key,value::bigint FROM jsonb_each_text(metadata->'weights') ORDER BY key COLLATE "C"
    ON CONFLICT(key) DO UPDATE SET revision=kaname.authority_policy_epoch.revision+EXCLUDED.revision;
   UPDATE kaname.authority_forward_emit_anchor_v4 SET write_batch=jsonb_set(write_batch,'{phase}','"policy-complete"'::jsonb)
   WHERE backend=pg_backend_pid() AND transaction_id=pg_current_xact_id() AND nonce=(metadata->>'nonce')::uuid
    AND NOT finished AND write_batch->>'phase'='empty-update';
   IF NOT FOUND THEN RAISE EXCEPTION 'native write policy replay' USING ERRCODE='42501';END IF;
   RETURN NULL;
  END IF;
 END IF;
 -- Только actual OLD переход exact unsigned native command получает веса.
 IF TG_TABLE_NAME='relation_fact' AND TG_OP='DELETE' THEN
  metadata:=kaname.authority_native_delete_batch_read_v4();
  IF metadata IS NOT NULL THEN
   IF TG_RELID<>'kaname.relation_fact'::regclass OR TG_LEVEL<>'STATEMENT' OR TG_WHEN<>'AFTER'
    OR metadata->>'phase'<>'deleting' OR pg_trigger_depth()<>2 THEN
    RAISE EXCEPTION 'native batch policy phase or invocation changed' USING ERRCODE='42501';END IF;
   -- NULL не должен совпасть с NULL через set operation; ordinary OLD обязан быть editor.
   IF EXISTS(SELECT 1 FROM old_policy_rows o WHERE o.relation IS DISTINCT FROM 'editor'
    OR o.subject IS NULL OR o.object_type IS NULL OR o.object_id IS NULL) THEN
    RAISE EXCEPTION 'native batch actual OLD outside exact command' USING ERRCODE='42501';END IF;
   -- Разность immutable command keys и actual OLD не требует попарного поиска.
   -- Holder reads остаются прежними fresh invoker statements после fact locks.
   IF EXISTS(SELECT o.subject,o.object_type||':'||o.object_id FROM old_policy_rows o
    EXCEPT
    SELECT j#>>'{payload,user}',j#>>'{payload,object}' FROM jsonb_array_elements(metadata->'rows') j
    WHERE j->>'event_type'='fga.tuple.delete') THEN
    RAISE EXCEPTION 'native batch actual OLD outside exact command' USING ERRCODE='42501';END IF;
   -- DISTINCT внутри исторического DELETE; SUM между разными actual OLD.
   IF EXISTS(SELECT 1 FROM old_policy_rows o CROSS JOIN LATERAL
    (SELECT array_agg(DISTINCT x) ks FROM unnest(kaname.authority_policy_keys('relation_fact',to_jsonb(o))) x) k
    WHERE '*'=ANY(k.ks) OR cardinality(k.ks)>4096) THEN
    RAISE EXCEPTION 'native batch policy root eligibility changed' USING ERRCODE='42501';END IF;
   IF EXISTS(SELECT 1 FROM old_policy_rows) THEN
    PERFORM key FROM kaname.authority_policy_epoch WHERE key='*' FOR SHARE;
    INSERT INTO kaname.authority_policy_epoch(key,revision)
    SELECT q.k,count(*) FROM old_policy_rows o CROSS JOIN LATERAL
     (SELECT DISTINCT x COLLATE "C" k FROM unnest(kaname.authority_policy_keys('relation_fact',to_jsonb(o))) x) q
    GROUP BY q.k ORDER BY q.k COLLATE "C"
    ON CONFLICT(key) DO UPDATE SET revision=kaname.authority_policy_epoch.revision+EXCLUDED.revision;
   END IF;
   UPDATE kaname.authority_forward_emit_anchor_v4 SET batch=jsonb_set(batch,'{phase}','"policy-complete"'::jsonb)
    ||jsonb_build_object('deleted_count',(SELECT count(*) FROM old_policy_rows))
   WHERE backend=pg_backend_pid() AND transaction_id=pg_current_xact_id() AND nonce=(metadata->>'nonce')::uuid
    AND NOT finished AND batch->>'phase'='deleting';
   IF NOT FOUND THEN RAISE EXCEPTION 'native batch policy replay' USING ERRCODE='42501';END IF;
   RETURN NULL;
  END IF;
 END IF;
 -- Для этих таблиц historical policy trigger отсутствовал.
 IF TG_TABLE_NAME IN ('access_binding_target_members','access_binding_emitted_tuples','resource_registration_pointer','fga_outbox') THEN RETURN NULL; END IF;
 IF TG_OP='UPDATE' THEN
  SELECT pg_catalog.array_agg(DISTINCT q.k COLLATE "C" ORDER BY q.k COLLATE "C") INTO keys FROM (
   SELECT unnest(kaname.authority_policy_keys(TG_TABLE_NAME,to_jsonb(o))) k FROM old_policy_rows o
   UNION SELECT unnest(kaname.authority_policy_keys(TG_TABLE_NAME,to_jsonb(n))) FROM new_policy_rows n) q;
  -- Смена родителя меняет ownership уже известного источника. Это редкая
  -- неоднозначная структурная мутация, заранее требующая GLOBAL writer.
  IF TG_TABLE_NAME IN ('projects','roles') THEN
   SELECT EXISTS(SELECT 1 FROM old_policy_rows o JOIN new_policy_rows n ON to_jsonb(o)->>'id'=to_jsonb(n)->>'id'
    WHERE (to_jsonb(o)->'account_id',to_jsonb(o)->'project_id',to_jsonb(o)->'is_system') IS DISTINCT FROM
          (to_jsonb(n)->'account_id',to_jsonb(n)->'project_id',to_jsonb(n)->'is_system')) INTO moved;
  END IF;
 ELSIF TG_OP='INSERT' THEN
  SELECT pg_catalog.array_agg(DISTINCT q.k COLLATE "C" ORDER BY q.k COLLATE "C") INTO keys FROM (SELECT unnest(kaname.authority_policy_keys(TG_TABLE_NAME,to_jsonb(n))) k FROM new_policy_rows n) q;
 ELSIF TG_OP='DELETE' THEN
  SELECT pg_catalog.array_agg(DISTINCT q.k COLLATE "C" ORDER BY q.k COLLATE "C") INTO keys FROM (SELECT unnest(kaname.authority_policy_keys(TG_TABLE_NAME,to_jsonb(o))) k FROM old_policy_rows o) q;
  IF TG_TABLE_NAME='projects' THEN moved:=true; END IF;
 ELSE moved:=true;
 END IF;
 IF moved OR pg_catalog.cardinality(keys)>4096 THEN keys:=ARRAY['*']; END IF;
 IF keys IS NULL THEN RETURN NULL; END IF;
 -- Порядок root -> typed keys совпадает с protect. Root не меняется от
 -- обычных account/actor writes; его shared locks совместимы друг с другом.
 IF '*'=ANY(keys) THEN UPDATE kaname.authority_policy_epoch SET revision=revision+1 WHERE key='*';
 ELSE PERFORM key FROM kaname.authority_policy_epoch WHERE key='*' FOR SHARE; END IF;
 -- keys уже DISTINCT и отсортирован по COLLATE "C" во всех трёх конструкторах.
 FOREACH k IN ARRAY keys LOOP
  IF k IS NULL OR k='*' THEN CONTINUE; END IF;
  IF TG_TABLE_NAME IN ('access_bindings','access_binding_subjects') AND k LIKE 'carrier_latch:role:%' THEN
   -- Binding держит только SHARE latch. Revision не блокируется во время apply.
   PERFORM key FROM kaname.authority_policy_epoch WHERE key=k FOR SHARE;
   IF NOT FOUND THEN RAISE EXCEPTION 'carrier latch missing' USING ERRCODE='40001'; END IF;
   INSERT INTO kaname.authority_policy_carrier_pending(transaction_id,backend_pid,role_id)
    VALUES(pg_current_xact_id(),pg_backend_pid(),substr(k,length('carrier_latch:role:')+1)) ON CONFLICT DO NOTHING;
  ELSE
   INSERT INTO kaname.authority_policy_epoch(key,revision) VALUES(k,1)
   ON CONFLICT(key) DO UPDATE SET revision=kaname.authority_policy_epoch.revision+1;
  END IF;
 END LOOP;
 -- Epoch rows никогда не удаляются вместе с источником: delete/recreate
 -- сохраняет монотонное поколение, а переустановка миграции меняет generation.
 RETURN NULL;
END $$;
-- +goose StatementEnd


-- +goose StatementBegin
CREATE FUNCTION kaname.authority_binding_command_begin_v3(p_command jsonb) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;metadata jsonb;program record;snapshot jsonb;storage oid;owner_oid oid;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'binding'
 OR proof->>'purpose' IS DISTINCT FROM 'participant'
 OR coalesce(proof->>'mode','') NOT IN ('accounts','global') THEN
  RAISE EXCEPTION 'binding command requires authenticated participant' USING ERRCODE='42501';END IF;
 metadata:=kaname._authority_binding_mirror_store_v3();
 IF metadata IS NULL THEN
  -- Отсутствие owner program не даёт caller обходить обязательный mirror stage.
  IF to_regclass('pg_temp.kaname_binding_sequence_snapshot') IS NOT NULL THEN
   -- На каждом Begin заново проверяются те же owner/ACL/identity/lifetime guards.
   -- Для запрета обхода нужен только header и наличие mirror: сериализация всех
   -- commands/maximum на каждом ordinal давала квадратичную работу group stage.
   -- proof получен в начале этого вызова; до этой точки были только private reads.
   -- Cursor/identity не кешируются между вызовами и не передаются caller.
   IF proof IS NULL OR proof->>'kind'<>'binding' OR proof->>'purpose'<>'participant' THEN
    RAISE EXCEPTION 'binding stage participant required' USING ERRCODE='42501';END IF;
   storage:=to_regclass('pg_temp.kaname_binding_sequence_snapshot');
   SELECT oid INTO STRICT owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
   IF storage IS NULL OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=storage AND c.relowner=owner_oid AND c.relpersistence='t' AND c.relkind='r')
   OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE c.oid=storage AND a.grantee<>owner_oid) THEN
    RAISE EXCEPTION 'untrusted binding owner snapshot' USING ERRCODE='42501';END IF;
   SELECT jsonb_build_object('backend',s.backend,'invoker_oid',s.invoker_oid,'stage_xid',s.stage_xid,
    'model_id',s.model_id,'catalog_id',s.catalog_id,'projector_version',s.projector_version,
    'has_mirror',s.mirror IS NOT NULL AND s.mirror<>'null'::jsonb)
   INTO STRICT snapshot FROM pg_temp.kaname_binding_sequence_snapshot s WHERE singleton;
   IF snapshot->>'backend' IS DISTINCT FROM proof->>'backend' OR snapshot->>'invoker_oid' IS DISTINCT FROM proof->>'invoker_oid'
   OR snapshot->>'stage_xid'=proof->>'transaction_id' OR snapshot->>'model_id' IS DISTINCT FROM proof->>'model_id'
   OR snapshot->>'catalog_id' IS DISTINCT FROM proof->>'catalog_id' OR snapshot->>'projector_version' IS DISTINCT FROM proof->>'projector_version' THEN
    RAISE EXCEPTION 'binding owner snapshot identity/lifetime changed' USING ERRCODE='P1034';END IF;
   IF (snapshot->>'has_mirror')::boolean THEN
    RAISE EXCEPTION 'binding mirror command program missing' USING ERRCODE='42501';END IF;
  END IF;
  RETURN false;
 END IF;
 SELECT p.* INTO STRICT program FROM pg_temp.kaname_binding_mirror_program p WHERE singleton;
 IF metadata->>'final_clock' IS DISTINCT FROM proof->>'decision_at'
 OR program.final_clock IS NULL OR program.active_command IS NOT NULL
 OR program.next_command>jsonb_array_length(program.commands)
 OR p_command IS NULL OR program.commands->(program.next_command-1) IS DISTINCT FROM p_command THEN
  RAISE EXCEPTION 'binding command differs from next owner operation' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_binding_mirror_program SET active_command=next_command WHERE singleton;
 RETURN true;
END $$;

CREATE FUNCTION kaname.authority_binding_command_end_v3(p_command jsonb) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;program record;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'binding'
 OR proof->>'purpose' IS DISTINCT FROM 'participant'
 OR coalesce(proof->>'mode','') NOT IN ('accounts','global') THEN
  RAISE EXCEPTION 'binding command requires authenticated participant' USING ERRCODE='42501';END IF;
 IF kaname._authority_binding_mirror_store_v3() IS NULL THEN RAISE EXCEPTION 'binding command program absent' USING ERRCODE='42501';END IF;
 SELECT p.* INTO STRICT program FROM pg_temp.kaname_binding_mirror_program p WHERE singleton;
 IF program.active_command IS NULL OR program.active_command<>program.next_command
 OR p_command IS NULL OR program.commands->(program.active_command-1) IS DISTINCT FROM p_command
 OR program.audit_rows ? program.active_command::text
 OR EXISTS(SELECT 1 FROM pg_temp.kaname_binding_mirror_images i WHERE i.command_no=program.active_command
  AND ((i.required AND NOT i.consumed) OR (i.table_name='fga_outbox' AND NOT i.folded))) THEN
  RAISE EXCEPTION 'binding command required effects incomplete' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_binding_mirror_program SET active_command=NULL,next_command=next_command+1 WHERE singleton;
END $$;

CREATE FUNCTION kaname.authority_binding_command_audit_v3(p_command jsonb) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;program record;row_value jsonb;actual jsonb;invoker oid;snapshot jsonb;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'binding'
 OR proof->>'purpose' IS DISTINCT FROM 'participant'
 OR coalesce(proof->>'mode','') NOT IN ('accounts','global') THEN
  RAISE EXCEPTION 'binding command requires authenticated participant' USING ERRCODE='42501';END IF;
 IF kaname._authority_binding_mirror_store_v3() IS NULL THEN
  IF to_regclass('pg_temp.kaname_binding_sequence_snapshot') IS NOT NULL THEN
   snapshot:=kaname._authority_binding_stage_snapshot_v3();
   IF snapshot->'mirror' IS NOT NULL AND snapshot->'mirror'<>'null'::jsonb THEN
    RAISE EXCEPTION 'binding audit owner program missing' USING ERRCODE='42501';END IF;
  END IF;
  RETURN false;END IF;
 SELECT p.* INTO STRICT program FROM pg_temp.kaname_binding_mirror_program p WHERE singleton;
 IF program.active_command IS NULL OR p_command->>'Kind' IS DISTINCT FROM 'audit'
 OR program.commands->(program.active_command-1) IS DISTINCT FROM p_command THEN
  RAISE EXCEPTION 'binding audit command differs from owner operation' USING ERRCODE='42501';END IF;
 row_value:=program.audit_rows->program.active_command::text;
 invoker:=(kaname.authority_protocol_attestation()->>'invoker_oid')::oid;
 IF row_value IS NULL OR NOT has_table_privilege(invoker,'kaname.audit_outbox','INSERT') THEN
  RAISE EXCEPTION 'binding audit row or original ACL absent' USING ERRCODE='42501';END IF;
 INSERT INTO kaname.audit_outbox(id,event_type,tenant_account_id,event_payload,status,attempts,created_at,next_attempt_at)
 VALUES(row_value->>'id',row_value->>'event_type',row_value->>'tenant_account_id',row_value->'event_payload',
  row_value->>'status',(row_value->>'attempts')::integer,(row_value->>'created_at')::timestamptz,(row_value->>'next_attempt_at')::timestamptz)
 RETURNING to_jsonb(audit_outbox) INTO actual;
 IF actual IS DISTINCT FROM row_value THEN RAISE EXCEPTION 'binding audit actual row differs' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_binding_mirror_program SET audit_rows=audit_rows-program.active_command::text WHERE singleton;
 RETURN true;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$ DECLARE sig text;r record;BEGIN
 FOREACH sig IN ARRAY ARRAY['authority_binding_command_begin_v3(jsonb)','authority_binding_command_end_v3(jsonb)','authority_binding_command_audit_v3(jsonb)'] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM PUBLIC',sig);
  FOR r IN SELECT DISTINCT u.rolname FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a JOIN pg_catalog.pg_roles u ON u.oid=a.grantee
   WHERE p.oid=to_regprocedure('kaname.'||sig) AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM %I',sig,r.rolname);
  END LOOP;
 END LOOP;
END $$;
-- +goose StatementEnd


-- +goose StatementBegin
CREATE FUNCTION kaname._authority_binding_mirror_policy_prepare_v3(p_snapshot jsonb) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;mirror jsonb;keys text[];k text;owner_oid oid;r record;receipt record;reads integer;rows integer;
BEGIN
 proof:=kaname.authority_protocol_attestation();mirror:=p_snapshot->'mirror';
 IF mirror IS NULL OR mirror='null'::jsonb THEN RETURN;END IF;
 IF p_snapshot IS DISTINCT FROM kaname._authority_binding_stage_snapshot_v3()
 OR proof->>'kind' IS DISTINCT FROM 'binding' OR proof->>'purpose' IS DISTINCT FROM 'participant'
 OR proof->>'mode' IS DISTINCT FROM 'accounts' OR current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'binding policy prelock lacks owner stage' USING ERRCODE='42501';END IF;
 SELECT oid INTO STRICT owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
 IF to_regclass('pg_temp.kaname_binding_mirror_policy_receipt') IS NOT NULL THEN
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid='pg_temp.kaname_binding_mirror_policy_receipt'::regclass
   AND c.relowner=owner_oid AND c.relpersistence='t' AND c.relkind='r')
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
   WHERE c.oid='pg_temp.kaname_binding_mirror_policy_receipt'::regclass AND a.grantee<>owner_oid) THEN
   RAISE EXCEPTION 'untrusted binding policy receipt' USING ERRCODE='42501';END IF;
  SELECT * INTO STRICT receipt FROM pg_temp.kaname_binding_mirror_policy_receipt WHERE singleton;
  IF receipt.identity IS DISTINCT FROM proof-ARRAY['decision_at'] OR receipt.binding_id IS DISTINCT FROM p_snapshot->>'binding_id' THEN
   RAISE EXCEPTION 'binding policy receipt identity changed' USING ERRCODE='42501';END IF;
  RETURN;
 END IF;
 IF jsonb_typeof(mirror->'policy_objects') IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'binding policy object closure absent' USING ERRCODE='42501';END IF;
 SELECT array_agg(DISTINCT key_value COLLATE "C" ORDER BY key_value COLLATE "C") INTO keys FROM (
  SELECT jsonb_array_elements_text(o.value) AS key_value FROM jsonb_each(mirror->'policy_objects') o
  UNION ALL
  SELECT CASE WHEN t->>'User' ~ '^(user|service_account):[^#*]+$' THEN t->>'User'
   WHEN t->>'User' ~ '^(group|iam_group):[^#*]+#member$' THEN 'group:'||split_part(split_part(t->>'User',':',2),'#',1)
   WHEN t->>'User' ~ '^(account|project|cluster):[^#*]+$' THEN NULL ELSE '*' END
  FROM jsonb_array_elements(mirror->'commands') c CROSS JOIN LATERAL jsonb_array_elements(coalesce(nullif(c->'Tuples','null'::jsonb),'[]'::jsonb)) t
 ) q WHERE key_value IS NOT NULL;
 keys:=coalesce(keys,ARRAY[]::text[]);reads:=1+cardinality(array_remove(keys,'*'));rows:=1+cardinality(array_remove(keys,'*'));
 IF cardinality(keys)>4096 OR reads>(mirror->>'budget_reads')::integer OR rows>(mirror->>'budget_rows')::integer THEN
  RAISE EXCEPTION 'binding policy early lock budget exceeded' USING ERRCODE='54000';END IF;
 LOCK TABLE kaname.authority_policy_epoch IN ROW EXCLUSIVE MODE;
 IF '*'=ANY(keys) THEN PERFORM key FROM kaname.authority_policy_epoch WHERE key='*' FOR UPDATE;
 ELSE PERFORM key FROM kaname.authority_policy_epoch WHERE key='*' FOR SHARE;END IF;
 IF NOT FOUND THEN RAISE EXCEPTION 'binding policy ROOT absent' USING ERRCODE='40001';END IF;
 FOR k IN SELECT value FROM unnest(keys) value WHERE value<>'*' ORDER BY value COLLATE "C" LOOP
  INSERT INTO kaname.authority_policy_epoch(key) VALUES(k) ON CONFLICT DO NOTHING;
  PERFORM key FROM kaname.authority_policy_epoch WHERE key=k FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'binding policy typed key absent' USING ERRCODE='40001';END IF;
 END LOOP;
 CREATE TEMP TABLE kaname_binding_mirror_policy_receipt(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
  identity jsonb NOT NULL,binding_id text NOT NULL,keys jsonb NOT NULL,logical_reads integer NOT NULL,logical_rows integer NOT NULL) ON COMMIT DROP;
 REVOKE ALL ON pg_temp.kaname_binding_mirror_policy_receipt FROM PUBLIC;
 FOR r IN SELECT DISTINCT u.rolname FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_catalog.pg_roles u ON u.oid=a.grantee
  WHERE c.oid='pg_temp.kaname_binding_mirror_policy_receipt'::regclass AND a.grantee<>owner_oid LOOP
  EXECUTE format('REVOKE ALL ON pg_temp.kaname_binding_mirror_policy_receipt FROM %I',r.rolname);
 END LOOP;
 INSERT INTO pg_temp.kaname_binding_mirror_policy_receipt(identity,binding_id,keys,logical_reads,logical_rows)
 VALUES(proof-ARRAY['decision_at'],p_snapshot->>'binding_id',to_jsonb(keys),reads,rows);
END $$;
REVOKE ALL ON FUNCTION kaname._authority_binding_mirror_policy_prepare_v3(jsonb) FROM PUBLIC;
DO $$ DECLARE r record;BEGIN
 FOR r IN SELECT DISTINCT u.rolname FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_catalog.pg_roles u ON u.oid=a.grantee
 WHERE p.oid='kaname._authority_binding_mirror_policy_prepare_v3(jsonb)'::regprocedure AND a.grantee<>p.proowner LOOP
 EXECUTE format('REVOKE ALL ON FUNCTION kaname._authority_binding_mirror_policy_prepare_v3(jsonb) FROM %I',r.rolname);END LOOP;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_audit_id_guard_v2() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;row_value jsonb;matches integer;program record;hashed integer;
BEGIN
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME<>'audit_outbox' OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW'
 OR TG_OP NOT IN ('INSERT','UPDATE') THEN RAISE EXCEPTION 'invalid audit ID guard context' USING ERRCODE='42501';END IF;
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NULL THEN
  IF kaname._authority_audit_binding_store_v3() IS NOT NULL THEN
   SELECT p.* INTO STRICT program FROM pg_temp.kaname_binding_mirror_program p WHERE singleton;
   hashed:=hashtext(NEW.id);
   IF TG_OP<>'INSERT' OR program.active_command IS NULL OR program.commands->(program.active_command-1)->>'Kind'<>'audit'
   OR program.audit_rows->program.active_command::text IS DISTINCT FROM to_jsonb(NEW)
   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='advisory'
    AND l.database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()) AND l.classid=1262569298::oid
    AND l.objid=(hashed::bigint & 4294967295)::oid AND l.objsubid=2 AND l.mode='ExclusiveLock' AND l.granted) THEN
    RAISE EXCEPTION 'binding audit lacks exact active row and preheld key' USING ERRCODE='42501';END IF;
   RETURN NEW;
  END IF;
  PERFORM pg_advisory_xact_lock(1262569298,hashtext(NEW.id));
  RETURN NEW;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Resource cannot update audit row' USING ERRCODE='42501';END IF;
 PERFORM kaname._authority_resource_preheld_key_v2(1262569298,NEW.id,true);
 row_value:=to_jsonb(NEW);
 SELECT count(*) INTO matches FROM jsonb_array_elements(CASE WHEN manifest->'intent'->>'kind'='object'
   THEN manifest#>'{object_physical,audits}' ELSE manifest#>'{registration_physical,audits}' END) a
  WHERE a->'row'=row_value AND a->'command'=manifest->'object_command';
 IF matches<>1 OR coalesce((manifest->'consumed_audit_ids') ? NEW.id,true) THEN
  RAISE EXCEPTION 'audit insert outside exact private program' USING ERRCODE='42501';END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION kaname.authority_audit_applied_v2() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;program record;
BEGIN
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME<>'audit_outbox' OR TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' THEN
  RAISE EXCEPTION 'invalid audit applied context' USING ERRCODE='42501';END IF;
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NULL THEN
  IF kaname._authority_audit_binding_store_v3() IS NOT NULL THEN
   SELECT p.* INTO STRICT program FROM pg_temp.kaname_binding_mirror_program p WHERE singleton;
   IF program.active_command IS NULL OR program.audit_rows->program.active_command::text IS DISTINCT FROM to_jsonb(NEW) THEN
    RAISE EXCEPTION 'binding audit actual row is unprepared' USING ERRCODE='42501';END IF;
   UPDATE pg_temp.kaname_binding_mirror_program SET audit_rows=audit_rows-program.active_command::text WHERE singleton;
  END IF;
  RETURN NULL;END IF;
 IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN manifest->'intent'->>'kind'='object'
   THEN manifest#>'{object_physical,audits}' ELSE manifest#>'{registration_physical,audits}' END) a WHERE a->'row'=to_jsonb(NEW) AND a->'command'=manifest->'object_command') THEN
  RAISE EXCEPTION 'unverified audit applied' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_authority_resource_manifest SET consumed_audit_ids=array_append(consumed_audit_ids,NEW.id);
 RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION kaname.authority_audit_statement_guard_v2() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF kaname._authority_audit_binding_store_v3() IS NOT NULL THEN
  RAISE EXCEPTION 'binding audit mutation outside INSERT program' USING ERRCODE='42501';END IF;
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME<>'audit_outbox' OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'STATEMENT'
 OR TG_OP NOT IN ('UPDATE','DELETE','TRUNCATE') THEN
  RAISE EXCEPTION 'invalid audit statement guard context' USING ERRCODE='42501';END IF;
 IF kaname._authority_producer_resource_v2() IS NOT NULL THEN
  RAISE EXCEPTION 'Resource audit is append-only exact program' USING ERRCODE='42501';END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$ DECLARE signature text;r record;BEGIN
 FOREACH signature IN ARRAY ARRAY['_authority_group_add_program_v3()','authority_group_add_prepare_v3(jsonb,integer,integer)','authority_group_add_finalize_v3(jsonb,integer,integer)','_authority_group_add_row_v3(text,text,jsonb,jsonb)','_authority_group_add_statement_v3(text,text)','authority_group_add_fold_v3(text,jsonb,timestamptz)','authority_group_add_subject_id_v3()','_authority_group_add_subject_v3(text,text,jsonb)','_authority_group_add_complete_v3()','_authority_group_add_storage_v3()'] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM PUBLIC',signature);
  FOR r IN SELECT DISTINCT u.rolname FROM pg_catalog.pg_proc f CROSS JOIN LATERAL aclexplode(f.proacl) a
   JOIN pg_catalog.pg_roles u ON u.oid=a.grantee WHERE f.oid=to_regprocedure('kaname.'||signature) AND a.grantee<>f.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM %I',signature,r.rolname);
  END LOOP;
 END LOOP;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$ DECLARE r record;sig text;BEGIN
 IF NOT kaname._authority_full_contract_storage_v3() THEN
  RAISE EXCEPTION 'binding command pre-export closure incomplete' USING ERRCODE='55000';END IF;
 FOR r IN SELECT DISTINCT u.rolname FROM pg_catalog.pg_proc p
 CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_catalog.pg_roles u ON u.oid=a.grantee
 WHERE p.oid='kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'::regprocedure
 AND a.grantee<>p.proowner AND a.privilege_type='EXECUTE' AND NOT a.is_grantable LOOP
  FOREACH sig IN ARRAY ARRAY['authority_binding_command_begin_v3(jsonb)','authority_binding_command_end_v3(jsonb)','authority_binding_command_audit_v3(jsonb)'] LOOP
   EXECUTE format('GRANT EXECUTE ON FUNCTION kaname.%s TO %I',sig,r.rolname);
  END LOOP;
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$ DECLARE signature text;r record;BEGIN
 FOR r IN SELECT DISTINCT u.rolname FROM pg_catalog.pg_proc f CROSS JOIN LATERAL aclexplode(f.proacl) a
  JOIN pg_catalog.pg_roles u ON u.oid=a.grantee
  WHERE f.oid='kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'::regprocedure
   AND a.grantee<>f.proowner AND a.privilege_type='EXECUTE' LOOP
  FOREACH signature IN ARRAY ARRAY['authority_native_write_arm_v4(uuid)','authority_native_write_read_v4()','authority_native_delete_batch_read_v4()','authority_native_delete_emit_v4(jsonb[])','authority_native_delete_prepare_v4(jsonb[])','authority_native_delete_stamp_v4(uuid,bigint,jsonb)','authority_forward_emit_v4(jsonb[])','authority_forward_prepare_v4(jsonb[])','authority_forward_claim_v4(uuid)','authority_forward_finish_v4(uuid)','authority_group_add_prepare_v3(jsonb,integer,integer)','authority_group_add_finalize_v3(jsonb,integer,integer)','authority_group_add_fold_v3(text,jsonb,timestamptz)','authority_group_add_subject_id_v3()'] LOOP
   EXECUTE format('GRANT EXECUTE ON FUNCTION kaname.%s TO %I',signature,r.rolname);
  END LOOP;
 END LOOP;
END $$;
-- +goose StatementEnd
-- role_id и live имеют NOT NULL; CHECK (live) закрепляет true.
-- Составной role_live_fk сохраняет ссылку на существующую живую роль
-- и тот же ON DELETE CASCADE без второго FK callback на каждую строку.
ALTER TABLE ONLY kaname.access_binding_target_members
    DROP CONSTRAINT access_binding_target_members_role_fk;

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
-- Восстановление определения FK предшествующей схемы.
ALTER TABLE ONLY kaname.access_binding_target_members
    ADD CONSTRAINT access_binding_target_members_role_fk FOREIGN KEY (role_id) REFERENCES kaname.roles(id) ON DELETE CASCADE;
-- +goose StatementBegin

DROP TRIGGER relation_fact_00_native_batch ON kaname.fga_outbox;
DROP TRIGGER relation_fact_zz_native_batch ON kaname.fga_outbox;
CREATE OR REPLACE FUNCTION kaname.relation_fact_from_journal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    r record;
BEGIN
    -- Общий порядок захвата строк факта: по ключу (объект, субъект) побайтно;
    -- строки одного ключа — в порядке их появления, который задал писатель.
    FOR r IN
        SELECT j.event_type, j.payload, j.created_at
          FROM journal_rows j
         ORDER BY j.payload ->> 'object' COLLATE "C",
                  j.payload ->> 'user'   COLLATE "C",
                  j.id
    LOOP
        PERFORM kaname.relation_fact_fold_row(r.event_type, r.payload, r.created_at);
    END LOOP;
    RETURN NULL;
END $$;
DROP FUNCTION kaname._authority_native_delete_batch_begin_v4();
DROP FUNCTION kaname._authority_native_delete_batch_end_v4();
DROP FUNCTION kaname.authority_native_delete_batch_read_v4();
DROP FUNCTION kaname._authority_native_delete_batch_graph_v4();
DROP FUNCTION kaname.authority_native_write_read_v4();
DROP FUNCTION kaname.authority_native_write_arm_v4(uuid);
DROP FUNCTION kaname._authority_native_write_closure_v4();
DROP FUNCTION kaname._authority_native_write_weights_v4(jsonb);


ALTER TABLE kaname.subject_change_outbox ALTER COLUMN id SET DEFAULT nextval('kaname.subject_change_outbox_id_seq'::regclass);
CREATE OR REPLACE FUNCTION kaname.relation_fact_fold_row(
    p_event_type text, p_payload jsonb, p_created_at timestamptz) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_delete_through timestamptz;
    v_user      text := p_payload ->> 'user';
    v_object    text := p_payload ->> 'object';
    -- Версия ВЛАДЕЛЬЦА. Есть только у строки, которую владелец упорядочил сам.
    v_owner     text := p_payload ->> 'source_version';
    v_version   timestamptz;
    v_relations text[];
    v_relation  text;
    v_type      text;
    v_id        text;
    v_colon     int;
    -- Условие, которое модель объявляет на прямом списке этого отношения для
    -- типа субъекта строки (`[user with mfa_fresh]`); пусто — безусловно.
    v_condition text;
    -- Хранимый субъект строки снятия (п. 4 шапки миграции kaname#829).
    v_stored    text;
BEGIN
    -- Signed Resource исполняет только private final программу без позднего
    -- holder lookup/clock/lock; legacy семантика ниже сохранена дословно.
    IF kaname.authority_resource_fold_body_v2(p_event_type,p_payload,p_created_at) THEN RETURN;END IF;
    -- Набор ВЫИГРЫВАЕТ у скаляра: на выдаче набора присутствуют оба поля, и
    -- скаляр там — эхо для пода прежнего выпуска, а не весь предмет строки.
    IF jsonb_array_length(coalesce(p_payload -> 'relations', '[]'::jsonb)) > 0 THEN
        -- Отношения набора — в ОБЩЕМ порядке, а не в порядке писателя: строка
        -- факта ключуется отношением, и два набора одного субъекта на одном
        -- объекте, перечисленные встречно, брали бы их блокировки встречно.
        SELECT array_agg(value ORDER BY value COLLATE "C") INTO v_relations
          FROM jsonb_array_elements_text(p_payload -> 'relations') AS value;
    ELSIF p_payload ->> 'relation' IS NOT NULL THEN
        v_relations := ARRAY[p_payload ->> 'relation'];
    END IF;

    IF v_user IS NULL OR v_relations IS NULL OR v_object IS NULL THEN
        RAISE EXCEPTION
            'fga_outbox: строка без user/relation/object (%). Прямой факт складывается из этого журнала, и строка, которую нельзя спроецировать, дала бы движку право, о котором своя БД не знает.',
            p_payload;
    END IF;

    -- Порядок строки. У строки, упорядоченной владельцем, его задаёт версия
    -- владельца: метка журнала — момент НАЧАЛА транзакции службы, и у снятия,
    -- начавшего транзакцию раньше открытия, она оказалась бы старше того, что
    -- снятие обязано снять. Неразбираемая версия роняет строку, а не
    -- подменяется меткой: молчаливая подмена вернула бы ровно тот порядок, от
    -- которого поле защищает.
    v_version := coalesce(v_owner::timestamptz, p_created_at);

    -- Глагол выводится из выдачи и копией не хранится (см. 0098). Набор из
    -- одних глаголов выходит здесь — до разбора объекта, как и одиночный.
    --
    -- ИСКЛЮЧЕНИЕ ОДНО: строка, упорядоченная владельцем, — публикация для
    -- анонимного чтения. Её не выводит ни одна выдача, и отброшенная здесь, она
    -- не существовала бы нигде (kaname#107).
    IF v_owner IS NULL THEN
        v_relations := ARRAY(SELECT r FROM unnest(v_relations) AS r WHERE r NOT LIKE 'v\_%');
        IF array_length(v_relations, 1) IS NULL THEN
            RETURN;
        END IF;
    END IF;

    v_colon := position(':' in v_object);
    IF v_colon <= 1 OR v_colon = length(v_object) THEN
        RAISE EXCEPTION
            'fga_outbox: объект % не имеет формы "<тип>:<идентификатор>" — спроецировать прямой факт нельзя.',
            v_object;
    END IF;
    v_type := substr(v_object, 1, v_colon - 1);
    v_id   := substr(v_object, v_colon + 1);

    IF v_type LIKE '%.%' THEN
        RAISE EXCEPTION
            'fga_outbox: тип объекта % назван словарём каталога. Вопрос о доступе приходит словарём модели прав, и такая строка не совпала бы ни с одним вопросом.',
            v_type;
    END IF;

    FOREACH v_relation IN ARRAY v_relations LOOP
        IF p_event_type = 'fga.tuple.write' THEN
            -- Условие прикладывает ПИСАТЕЛЬ, и только он: факт человека на
            -- условном отношении без условия значил бы безусловный допуск там,
            -- где модель объявляет допуск лишь при выполненном условии.
            -- Перечень — дословно `with`-записи канонической модели; гейт
            -- `TestConditionedRelationHasAProducer` сверяет его с моделью в обе
            -- стороны (запись модели без строки и строка без записи модели —
            -- находки).
            SELECT c.condition_name INTO v_condition
              FROM (VALUES
                    ('compute_instance', 'console', 'user', 'mfa_fresh'),
                    ('compute_instance', 'ssh',     'user', 'mfa_fresh')
                   ) AS c(object_type, relation, subject_type, condition_name)
             WHERE c.object_type = v_type AND c.relation = v_relation
               AND c.subject_type = split_part(v_user, ':', 1);

            INSERT INTO kaname.relation_fact
                   (object_type, object_id, relation, subject, source_version, created_at, condition_name)
            VALUES (v_type, v_id, v_relation, v_user, v_version, now(), coalesce(v_condition, ''))
            ON CONFLICT (object_type, object_id, relation, subject) DO UPDATE
               SET source_version = EXCLUDED.source_version,
                   condition_name = EXCLUDED.condition_name
             WHERE relation_fact.source_version < EXCLUDED.source_version;
        ELSIF p_event_type = 'fga.tuple.delete' THEN
            -- Снятие с подстановкой прежнего писателя снимает строку, в которую
            -- переезд (п. 3) перенёс то, что этот писатель когда-то положил:
            -- перевод тот же, что у переписи, по отношению (п. 4 шапки).
            v_stored := v_user;
            IF v_user = 'user:*' THEN
                v_stored := CASE WHEN v_relation = 'v_get' THEN 'system_class:anonymous'
                                 ELSE 'system_class:authenticated' END;
            END IF;
            -- Факт, выведенный выдачей (строка без версии владельца), снимается
            -- лишь тогда, когда его не держит больше НИКТО (п. 2 шапки). Сперва
            -- замок строки факта: снятие ждёт любого, кто держит её незафиксированной
            -- (выдачу, свёрнутую в той же строке, второе снятие), и вопрос «держит
            -- ли кто-то ещё» задаётся уже после его коммита, свежим снимком.
            -- Новый typed mixed-set также проверяет держателей legacy строки;
            -- флаг кладёт только внутренний combined-delete, не запрос клиента.
            IF v_owner IS NULL OR p_payload->'protect_holders' = 'true'::jsonb OR EXISTS (
                   SELECT 1 FROM kaname.resource_registration_pointer rp
                    WHERE rp.object_type=v_type AND rp.object_id=v_id AND rp.relation=v_relation AND rp.subject=v_stored) THEN
                PERFORM 1 FROM kaname.relation_fact
                 WHERE object_type = v_type AND object_id = v_id
                   AND relation = v_relation AND subject = v_stored
                   FOR UPDATE;
                IF NOT FOUND THEN
                    CONTINUE;
                END IF;
                IF EXISTS (
                       SELECT 1
                         FROM kaname.access_binding_emitted_tuples et
                         JOIN kaname.access_bindings ab ON ab.id = et.binding_id
                        WHERE et.object = v_object AND et.relation = v_relation
                          AND et.fga_user = v_stored AND ab.status = 'ACTIVE')
                   OR EXISTS (SELECT 1 FROM kaname.resource_registration_pointer rp
                               WHERE rp.object_type=v_type AND rp.object_id=v_id AND rp.relation=v_relation
                                 AND rp.subject=v_stored AND rp.active)
                   OR (v_type = 'cluster' AND v_relation = 'system_admin' AND EXISTS (
                       SELECT 1
                         FROM kaname.cluster_admin_grants g
                        WHERE g.cluster_id = v_id
                          AND g.subject_type || ':' || g.subject_id = v_stored
                          AND (g.granted_until IS NULL OR g.granted_until > clock_timestamp())))
                THEN
                    CONTINUE;
                END IF;
            END IF;
            v_delete_through := NULL;
            IF v_owner IS NULL AND v_relation IN ('project','parent','owner') THEN
                -- Отдельный свежий RC statement ПОСЛЕ fact lock и held read.
                -- Без обратного замка receipt: registrar меняет её ДО факта.
                SELECT delete_through INTO v_delete_through
                  FROM kaname.resource_registration_retirement
                 WHERE object_type=v_type AND object_id=v_id
                   AND relation=v_relation AND subject=v_stored;
            END IF;
            -- У exact named tuple последний держатель может уйти меткой AB,
            -- отличной от шкалы владельца. После fresh held-check снимаем его
            -- без произвольного повышения надгробия; stale owner не проходит
            -- сохранённую версию claim. Для legacy tuple сравнение прежнее.
            DELETE FROM kaname.relation_fact
             WHERE object_type = v_type AND object_id = v_id
               AND relation = v_relation AND subject = v_stored
               AND (source_version <= v_version
                    OR (v_owner IS NULL AND v_delete_through IS NOT NULL AND source_version <= v_delete_through) OR EXISTS (
                    SELECT 1 FROM kaname.resource_registration_pointer rp
                     WHERE rp.object_type=v_type AND rp.object_id=v_id
                       AND rp.relation=v_relation AND rp.subject=v_stored
                       AND NOT rp.active
                       AND (v_owner IS NULL OR rp.source_version <= v_version)));
        END IF;
    END LOOP;
    RETURN;
END $$;
CREATE OR REPLACE FUNCTION kaname.authority_subject_change_id_guard_v2() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;matches integer;
BEGIN
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME<>'subject_change_outbox' OR TG_WHEN<>'BEFORE'
 OR TG_LEVEL<>'ROW' OR TG_OP NOT IN ('INSERT','UPDATE') THEN
  RAISE EXCEPTION 'invalid subject_change ID guard context' USING ERRCODE='42501';END IF;
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NULL THEN PERFORM pg_advisory_xact_lock(1262569301,hashtext(NEW.id::text));RETURN NEW;END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Resource cannot update subject_change queue' USING ERRCODE='42501';END IF;
 PERFORM kaname._authority_resource_preheld_key_v2(1262569301,NEW.id::text,true);
 SELECT count(*) INTO matches FROM jsonb_array_elements(manifest#>'{registration_physical,subject_changes}') q
  WHERE q->'row'=to_jsonb(NEW) AND q->'command'=manifest->'object_command';
 IF matches<>1 OR coalesce((manifest->'consumed_subject_change_ids') @> jsonb_build_array(NEW.id),true) THEN
  RAISE EXCEPTION 'subject_change insert outside exact registration command' USING ERRCODE='42501';END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION kaname.authority_subject_change_applied_v2() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;
BEGIN
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME<>'subject_change_outbox' OR TG_WHEN<>'AFTER'
 OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' THEN RAISE EXCEPTION 'invalid subject_change applied context' USING ERRCODE='42501';END IF;
 manifest:=kaname._authority_producer_resource_v2();IF manifest IS NULL THEN RETURN NULL;END IF;
 IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(manifest#>'{registration_physical,subject_changes}') q
  WHERE q->'row'=to_jsonb(NEW) AND q->'command'=manifest->'object_command') THEN
  RAISE EXCEPTION 'unverified subject_change row applied' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_authority_resource_manifest SET consumed_subject_change_ids=array_append(consumed_subject_change_ids,NEW.id);
 RETURN NULL;
END $$;
CREATE OR REPLACE FUNCTION kaname.authority_subject_change_statement_guard_v2() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME<>'subject_change_outbox' OR TG_WHEN<>'BEFORE'
 OR TG_LEVEL<>'STATEMENT' OR TG_OP NOT IN ('UPDATE','DELETE','TRUNCATE') THEN
  RAISE EXCEPTION 'invalid subject_change statement guard context' USING ERRCODE='42501';END IF;
 IF kaname._authority_producer_resource_v2() IS NOT NULL THEN
  RAISE EXCEPTION 'Resource subject_change queue is append-only exact program' USING ERRCODE='42501';END IF;
 RETURN NULL;
END $$;
CREATE OR REPLACE FUNCTION kaname._authority_resource_subject_change_wait_v2(p_count integer,p_reads integer)
RETURNS TABLE(reserved_ids jsonb,held_relations jsonb,held_advisory jsonb,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;invoker oid;table_id oid;sequence_id oid;identifier bigint;item record;
 ids jsonb:='[]'::jsonb;locks jsonb:='[]'::jsonb;relations jsonb;used integer:=5;i integer;present boolean;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource' OR proof->>'purpose' IS DISTINCT FROM 'participant'
 OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_finalized' IS DISTINCT FROM 'false'
 OR proof->>'consumer_profile' NOT IN ('resource_pending','resource_source_pending')
 OR current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'subject_change reservation requires pending Resource RC' USING ERRCODE='42501';END IF;
 IF p_count IS NULL OR p_count<1 OR p_count>100000 OR p_reads IS NULL OR p_reads<5+2*p_count OR p_reads>4096 THEN
  RAISE EXCEPTION 'subject_change reservation budget exceeded' USING ERRCODE='54000';END IF;
 invoker:=(proof->>'invoker_oid')::oid;table_id:='kaname.subject_change_outbox'::regclass;
 IF NOT has_table_privilege(invoker,table_id,'INSERT') THEN
  RAISE EXCEPTION 'subject_change INSERT privilege required' USING ERRCODE='42501';END IF;
 LOCK TABLE ONLY kaname.subject_change_outbox IN ROW EXCLUSIVE MODE;
 SELECT to_regclass(pg_get_serial_sequence('kaname.subject_change_outbox','id')) INTO sequence_id;
 IF sequence_id IS NULL OR sequence_id<>'kaname.subject_change_outbox_id_seq'::regclass
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=table_id AND a.attname='id'
  AND a.atttypid='bigint'::regtype AND a.attidentity='' AND NOT a.attisdropped)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid=table_id AND a.attname='id' AND pg_get_expr(d.adbin,d.adrelid)=$default$nextval('kaname.subject_change_outbox_id_seq'::regclass)$default$)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid=table_id OR inhparent=table_id) THEN
  RAISE EXCEPTION 'subject_change physical identity schema changed' USING ERRCODE='42501';END IF;
 -- Прежний INSERT serial вызывает nextval от invoker: owner helper сохраняет
 -- USAGE либо UPDATE sequence, не добавляя SELECT на неё.
 IF NOT (has_sequence_privilege(invoker,sequence_id,'USAGE') OR has_sequence_privilege(invoker,sequence_id,'UPDATE')) THEN
  RAISE EXCEPTION 'subject change sequence privilege required' USING ERRCODE='42501';END IF;
 -- nextval удерживает relation lock до конца всей TX даже при savepoint rollback.
 FOR i IN 1..p_count LOOP
  identifier:=nextval(sequence_id);used:=used+1;
  IF identifier<=0 THEN RAISE EXCEPTION 'invalid reserved subject_change ID' USING ERRCODE='P1034';END IF;
  ids:=ids||jsonb_build_array(identifier);
 END LOOP;
 -- Замки уникальности совместимы с legacy INSERT/переносом ID через trigger.
 -- Сортировка по фактическому advisory hash исключает inversion внутри набора.
 FOR item IN SELECT DISTINCT hashtext(v#>>'{}') h FROM jsonb_array_elements(ids) v ORDER BY h LOOP
  PERFORM pg_advisory_xact_lock(1262569301,item.h);
  locks:=locks||jsonb_build_array(jsonb_build_object('classid',1262569301,'objid',(item.h::bigint & 4294967295),
   'objsubid',2,'mode','ExclusiveLock'));
 END LOOP;
 FOR identifier IN SELECT (v#>>'{}')::bigint FROM jsonb_array_elements(ids) v LOOP
  used:=used+1;present:=false;
  SELECT true INTO present FROM ONLY kaname.subject_change_outbox q WHERE q.id=identifier FOR UPDATE;
  IF coalesce(present,false) THEN RAISE EXCEPTION 'reserved subject_change ID already exists' USING ERRCODE='P1034';END IF;
 END LOOP;
 relations:=jsonb_build_array(jsonb_build_object('oid',table_id,'mode','RowExclusiveLock'),
  jsonb_build_object('oid',sequence_id,'mode','RowExclusiveLock'));
 RETURN QUERY SELECT ids,relations,locks,used;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_audit_id_guard_v2() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;row_value jsonb;matches integer;
BEGIN
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME<>'audit_outbox' OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW'
 OR TG_OP NOT IN ('INSERT','UPDATE') THEN RAISE EXCEPTION 'invalid audit ID guard context' USING ERRCODE='42501';END IF;
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NULL THEN
  PERFORM pg_advisory_xact_lock(1262569298,hashtext(NEW.id));
  RETURN NEW;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Resource cannot update audit row' USING ERRCODE='42501';END IF;
 PERFORM kaname._authority_resource_preheld_key_v2(1262569298,NEW.id,true);
 row_value:=to_jsonb(NEW);
 SELECT count(*) INTO matches FROM jsonb_array_elements(CASE WHEN manifest->'intent'->>'kind'='object'
   THEN manifest#>'{object_physical,audits}' ELSE manifest#>'{registration_physical,audits}' END) a
  WHERE a->'row'=row_value AND a->'command'=manifest->'object_command';
 IF matches<>1 OR coalesce((manifest->'consumed_audit_ids') ? NEW.id,true) THEN
  RAISE EXCEPTION 'audit insert outside exact private program' USING ERRCODE='42501';END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION kaname.authority_audit_applied_v2() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;
BEGIN
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME<>'audit_outbox' OR TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' THEN
  RAISE EXCEPTION 'invalid audit applied context' USING ERRCODE='42501';END IF;
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NULL THEN RETURN NULL;END IF;
 IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN manifest->'intent'->>'kind'='object'
   THEN manifest#>'{object_physical,audits}' ELSE manifest#>'{registration_physical,audits}' END) a WHERE a->'row'=to_jsonb(NEW) AND a->'command'=manifest->'object_command') THEN
  RAISE EXCEPTION 'unverified audit applied' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_authority_resource_manifest SET consumed_audit_ids=array_append(consumed_audit_ids,NEW.id);
 RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION kaname.authority_audit_statement_guard_v2() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME<>'audit_outbox' OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'STATEMENT'
 OR TG_OP NOT IN ('UPDATE','DELETE','TRUNCATE') THEN
  RAISE EXCEPTION 'invalid audit statement guard context' USING ERRCODE='42501';END IF;
 IF kaname._authority_producer_resource_v2() IS NOT NULL THEN
  RAISE EXCEPTION 'Resource audit is append-only exact program' USING ERRCODE='42501';END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd
DROP FUNCTION kaname._authority_binding_mirror_policy_prepare_v3(jsonb);

DROP FUNCTION kaname.authority_binding_command_audit_v3(jsonb);
DROP FUNCTION kaname.authority_binding_command_end_v3(jsonb);
DROP FUNCTION kaname.authority_binding_command_begin_v3(jsonb);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_policy_changed() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE keys text[]; k text; moved boolean:=false; manifest jsonb; image jsonb; metadata jsonb; resource_keys text[]; resource_roles text[];
BEGIN
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NOT NULL THEN
  IF TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'resource truncate denied' USING ERRCODE='42501'; END IF;
  resource_keys:=ARRAY[]::text[]; resource_roles:=ARRAY[]::text[];
  IF TG_OP<>'INSERT' THEN
   FOR image IN SELECT to_jsonb(o) FROM old_policy_rows o LOOP
    metadata:=kaname._authority_resource_side_v2(manifest,TG_TABLE_NAME,TG_OP,'old',image);
    resource_keys:=resource_keys||kaname._authority_resource_key_array_v2(metadata->'epoch_write_keys',false);
    resource_roles:=resource_roles||kaname._authority_resource_key_array_v2(metadata->'deferred_carrier_roles');
    SELECT coalesce(array_agg(DISTINCT x),ARRAY[]::text[]) INTO resource_keys FROM unnest(resource_keys) x;
    SELECT coalesce(array_agg(DISTINCT x),ARRAY[]::text[]) INTO resource_roles FROM unnest(resource_roles) x;
   END LOOP;
  END IF;
  IF TG_OP<>'DELETE' THEN
   FOR image IN SELECT to_jsonb(n) FROM new_policy_rows n LOOP
    metadata:=kaname._authority_resource_side_v2(manifest,TG_TABLE_NAME,TG_OP,'new',image);
    resource_keys:=resource_keys||kaname._authority_resource_key_array_v2(metadata->'epoch_write_keys',false);
    resource_roles:=resource_roles||kaname._authority_resource_key_array_v2(metadata->'deferred_carrier_roles');
    SELECT coalesce(array_agg(DISTINCT x),ARRAY[]::text[]) INTO resource_keys FROM unnest(resource_keys) x;
    SELECT coalesce(array_agg(DISTINCT x),ARRAY[]::text[]) INTO resource_roles FROM unnest(resource_roles) x;
   END LOOP;
  END IF;
  FOR k IN SELECT DISTINCT x COLLATE "C" FROM unnest(resource_keys) x ORDER BY 1 LOOP
   IF NOT ((manifest->'epoch_write_keys') ? k) THEN
    RAISE EXCEPTION 'resource epoch write was not prepared' USING ERRCODE='42501';
   END IF;
   PERFORM kaname._authority_resource_preheld_key_v2(1262569296,k,true);
   -- Ни INSERT, ни повторного FOR UPDATE после final clock.
   UPDATE kaname.authority_policy_epoch SET revision=revision+1 WHERE key=k;
   IF NOT FOUND THEN RAISE EXCEPTION 'resource prepared epoch missing' USING ERRCODE='40001'; END IF;
  END LOOP;
  FOR k IN SELECT DISTINCT x COLLATE "C" FROM unnest(resource_roles) x ORDER BY 1 LOOP
   -- Только queued carrier metadata; actual bump сохраняется в deferred flush.
   PERFORM kaname._authority_resource_preheld_key_v2(1262569296,'carrier_latch:role:'||k,false);
   PERFORM kaname._authority_resource_preheld_key_v2(1262569296,'carriers:role:'||k,true);
   INSERT INTO kaname.authority_policy_carrier_pending(transaction_id,backend_pid,role_id)
   VALUES(pg_current_xact_id(),pg_backend_pid(),k) ON CONFLICT DO NOTHING;
  END LOOP;
  RETURN NULL;
 END IF;
 -- Для этих таблиц historical policy trigger отсутствовал.
 IF TG_TABLE_NAME IN ('access_binding_target_members','access_binding_emitted_tuples','resource_registration_pointer','fga_outbox') THEN RETURN NULL; END IF;
 IF TG_OP='UPDATE' THEN
  SELECT pg_catalog.array_agg(DISTINCT q.k COLLATE "C" ORDER BY q.k COLLATE "C") INTO keys FROM (
   SELECT unnest(kaname.authority_policy_keys(TG_TABLE_NAME,to_jsonb(o))) k FROM old_policy_rows o
   UNION SELECT unnest(kaname.authority_policy_keys(TG_TABLE_NAME,to_jsonb(n))) FROM new_policy_rows n) q;
  -- Смена родителя меняет ownership уже известного источника. Это редкая
  -- неоднозначная структурная мутация, заранее требующая GLOBAL writer.
  IF TG_TABLE_NAME IN ('projects','roles') THEN
   SELECT EXISTS(SELECT 1 FROM old_policy_rows o JOIN new_policy_rows n ON to_jsonb(o)->>'id'=to_jsonb(n)->>'id'
    WHERE (to_jsonb(o)->'account_id',to_jsonb(o)->'project_id',to_jsonb(o)->'is_system') IS DISTINCT FROM
          (to_jsonb(n)->'account_id',to_jsonb(n)->'project_id',to_jsonb(n)->'is_system')) INTO moved;
  END IF;
 ELSIF TG_OP='INSERT' THEN
  SELECT pg_catalog.array_agg(DISTINCT q.k COLLATE "C" ORDER BY q.k COLLATE "C") INTO keys FROM (SELECT unnest(kaname.authority_policy_keys(TG_TABLE_NAME,to_jsonb(n))) k FROM new_policy_rows n) q;
 ELSIF TG_OP='DELETE' THEN
  SELECT pg_catalog.array_agg(DISTINCT q.k COLLATE "C" ORDER BY q.k COLLATE "C") INTO keys FROM (SELECT unnest(kaname.authority_policy_keys(TG_TABLE_NAME,to_jsonb(o))) k FROM old_policy_rows o) q;
  IF TG_TABLE_NAME='projects' THEN moved:=true; END IF;
 ELSE moved:=true;
 END IF;
 IF moved OR pg_catalog.cardinality(keys)>4096 THEN keys:=ARRAY['*']; END IF;
 IF keys IS NULL THEN RETURN NULL; END IF;
 -- Порядок root -> typed keys совпадает с protect. Root не меняется от
 -- обычных account/actor writes; его shared locks совместимы друг с другом.
 IF '*'=ANY(keys) THEN UPDATE kaname.authority_policy_epoch SET revision=revision+1 WHERE key='*';
 ELSE PERFORM key FROM kaname.authority_policy_epoch WHERE key='*' FOR SHARE; END IF;
 FOR k IN SELECT DISTINCT x COLLATE "C" FROM pg_catalog.unnest(keys) x WHERE x<>'*' ORDER BY 1 LOOP
  IF TG_TABLE_NAME IN ('access_bindings','access_binding_subjects') AND k LIKE 'carrier_latch:role:%' THEN
   -- Binding держит только SHARE latch. Revision не блокируется во время apply.
   PERFORM key FROM kaname.authority_policy_epoch WHERE key=k FOR SHARE;
   IF NOT FOUND THEN RAISE EXCEPTION 'carrier latch missing' USING ERRCODE='40001'; END IF;
   INSERT INTO kaname.authority_policy_carrier_pending(transaction_id,backend_pid,role_id)
    VALUES(pg_current_xact_id(),pg_backend_pid(),substr(k,length('carrier_latch:role:')+1)) ON CONFLICT DO NOTHING;
  ELSE
   INSERT INTO kaname.authority_policy_epoch(key,revision) VALUES(k,1)
   ON CONFLICT(key) DO UPDATE SET revision=kaname.authority_policy_epoch.revision+1;
  END IF;
 END LOOP;
 -- Epoch rows никогда не удаляются вместе с источником: delete/recreate
 -- сохраняет монотонное поколение, а переустановка миграции меняет generation.
 RETURN NULL;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_resource_effect_applied_v2() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb; old_image jsonb; new_image jsonb; matched jsonb;
 ordinal integer;
BEGIN
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NULL THEN RETURN NULL; END IF;
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP NOT IN ('INSERT','UPDATE','DELETE') THEN
  RAISE EXCEPTION 'resource applied-effect trigger context invalid' USING ERRCODE='42501';
 END IF;
 IF TG_OP<>'INSERT' THEN old_image:=to_jsonb(OLD); END IF;
 IF TG_OP<>'DELETE' THEN new_image:=to_jsonb(NEW); END IF;
 matched:=kaname._authority_resource_write_v2(manifest,TG_TABLE_NAME,TG_OP,old_image,new_image);
 IF jsonb_typeof(matched->'required') IS DISTINCT FROM 'boolean' THEN
  RAISE EXCEPTION 'resource effect obligation is missing' USING ERRCODE='42501';
 END IF;
 IF matched->>'required'='false' THEN
  -- Разрешение BEFORE на попытку INSERT не разрешает persisted INSERT:
  -- ожидаемый ON CONFLICT/DO NOTHING должен остаться без AFTER ROW эффекта.
  RAISE EXCEPTION 'resource attempted-only image persisted' USING ERRCODE='42501';
 END IF;
 IF TG_TABLE_NAME='fga_outbox' AND TG_OP='INSERT' THEN
  -- BEFORE guard уже одноразово выбрал разрешение без surrogate id. Из
  -- одинаковых разрешений учитывается лишь действительно потреблённое.
  SELECT e.ordinality::integer INTO ordinal
   FROM pg_temp.kaname_authority_resource_manifest r
   CROSS JOIN LATERAL jsonb_array_elements(r.writes) WITH ORDINALITY e(value,ordinality)
   WHERE e.value=matched AND e.ordinality::integer=ANY(r.consumed_outbox_writes)
    AND NOT e.ordinality::integer=ANY(r.consumed_required_writes)
   ORDER BY e.ordinality LIMIT 1;
 ELSE
  -- Повтор одного exact mandatory эффекта имеет отдельный ordinal.
  -- Удалять multiplicity нельзя: DELETE/recreate/DELETE обязан завершить
  -- оба удаления, а третий лишний actual эффект должен быть отвергнут.
  SELECT e.ordinality::integer INTO ordinal
   FROM pg_temp.kaname_authority_resource_manifest r
   CROSS JOIN LATERAL jsonb_array_elements(r.writes) WITH ORDINALITY e(value,ordinality)
   WHERE e.value=matched AND NOT e.ordinality::integer=ANY(r.consumed_required_writes)
   ORDER BY e.ordinality LIMIT 1;
 END IF;
 IF ordinal IS NULL THEN RAISE EXCEPTION 'resource applied effect was not prepared' USING ERRCODE='42501'; END IF;
 PERFORM kaname._authority_resource_consume_required_v2(ordinal);
 RETURN NULL;
END $$;
-- +goose StatementEnd


DROP TRIGGER binding_epoch_insert ON kaname.resource_registration_scope;
DROP TRIGGER binding_epoch_update ON kaname.resource_registration_scope;
DROP TRIGGER binding_epoch_delete ON kaname.resource_registration_scope;
DROP TRIGGER binding_epoch_truncate ON kaname.resource_registration_scope;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_binding_epoch_changed() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE keys text[]; k text; manifest jsonb; image jsonb; metadata jsonb; resource_keys text[]; resource_roles text[];
BEGIN
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NOT NULL THEN
  IF TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'resource truncate denied' USING ERRCODE='42501'; END IF;
  resource_keys:=ARRAY[]::text[]; resource_roles:=ARRAY[]::text[];
  IF TG_OP<>'INSERT' THEN
   FOR image IN SELECT to_jsonb(o) FROM old_epoch_rows o LOOP
    metadata:=kaname._authority_resource_side_v2(manifest,TG_TABLE_NAME,TG_OP,'old',image);
    resource_keys:=resource_keys||kaname._authority_resource_key_array_v2(metadata->'binding_epoch_write_scopes',true);
    resource_roles:=resource_roles||kaname._authority_resource_key_array_v2(metadata->'deferred_carrier_roles');
    SELECT coalesce(array_agg(DISTINCT x),ARRAY[]::text[]) INTO resource_keys FROM unnest(resource_keys) x;
    SELECT coalesce(array_agg(DISTINCT x),ARRAY[]::text[]) INTO resource_roles FROM unnest(resource_roles) x;
   END LOOP;
  END IF;
  IF TG_OP<>'DELETE' THEN
   FOR image IN SELECT to_jsonb(n) FROM new_epoch_rows n LOOP
    metadata:=kaname._authority_resource_side_v2(manifest,TG_TABLE_NAME,TG_OP,'new',image);
    resource_keys:=resource_keys||kaname._authority_resource_key_array_v2(metadata->'binding_epoch_write_scopes',true);
    resource_roles:=resource_roles||kaname._authority_resource_key_array_v2(metadata->'deferred_carrier_roles');
    SELECT coalesce(array_agg(DISTINCT x),ARRAY[]::text[]) INTO resource_keys FROM unnest(resource_keys) x;
    SELECT coalesce(array_agg(DISTINCT x),ARRAY[]::text[]) INTO resource_roles FROM unnest(resource_roles) x;
   END LOOP;
  END IF;
  FOR k IN SELECT DISTINCT x COLLATE "C" FROM unnest(resource_keys) x ORDER BY 1 LOOP
   IF NOT ((manifest->'binding_epoch_write_scopes') ? k) THEN
    RAISE EXCEPTION 'resource epoch write was not prepared' USING ERRCODE='42501';
   END IF;
   PERFORM kaname._authority_resource_preheld_key_v2(1262569297,k,true);
   -- Ни INSERT, ни повторного FOR UPDATE после final clock.
   UPDATE kaname.authority_binding_epoch SET revision=revision+1 WHERE scope=k;
   IF NOT FOUND THEN RAISE EXCEPTION 'resource prepared epoch missing' USING ERRCODE='40001'; END IF;
  END LOOP;
  RETURN NULL;
 END IF;
 -- Transition tables принадлежат executor этого statement, не search_path.
 -- По одному bump на distinct OLD+NEW account на statement, не на ledger row.
 IF TG_OP='UPDATE' THEN
  SELECT pg_catalog.array_agg(DISTINCT x ORDER BY x) INTO keys FROM (
   SELECT kaname.authority_binding_epoch_scope(TG_TABLE_NAME,pg_catalog.to_jsonb(o)) x FROM old_epoch_rows o
   UNION SELECT kaname.authority_binding_epoch_scope(TG_TABLE_NAME,pg_catalog.to_jsonb(n)) FROM new_epoch_rows n) s;
 ELSIF TG_OP='INSERT' THEN
  SELECT pg_catalog.array_agg(DISTINCT kaname.authority_binding_epoch_scope(TG_TABLE_NAME,pg_catalog.to_jsonb(n)) ORDER BY kaname.authority_binding_epoch_scope(TG_TABLE_NAME,pg_catalog.to_jsonb(n))) INTO keys FROM new_epoch_rows n;
 ELSIF TG_OP='DELETE' THEN
  SELECT pg_catalog.array_agg(DISTINCT kaname.authority_binding_epoch_scope(TG_TABLE_NAME,pg_catalog.to_jsonb(o)) ORDER BY kaname.authority_binding_epoch_scope(TG_TABLE_NAME,pg_catalog.to_jsonb(o))) INTO keys FROM old_epoch_rows o;
 ELSE keys:=ARRAY['']::text[];
 END IF;
 IF keys IS NULL THEN RETURN NULL; END IF;
 -- Глобальная строка shared для account writes: разные accounts не конфликтуют.
 -- Global source change конфликтует с любым apply snapshot.
 IF ''=ANY(keys) THEN
  UPDATE kaname.authority_binding_epoch SET revision=revision+1 WHERE scope='';
 ELSE
  PERFORM scope FROM kaname.authority_binding_epoch WHERE scope='' FOR KEY SHARE;
 END IF;
 FOREACH k IN ARRAY keys LOOP
  IF k<>'' THEN INSERT INTO kaname.authority_binding_epoch(scope,revision) VALUES(k,1)
   ON CONFLICT(scope) DO UPDATE SET revision=kaname.authority_binding_epoch.revision+1; END IF;
 END LOOP;
 RETURN NULL;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_binding_epoch_lock(p_accounts text[],p_expected jsonb) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; actual jsonb; at_time timestamptz;
BEGIN
 IF p_expected IS NULL OR pg_catalog.jsonb_typeof(p_expected)<>'object' THEN RAISE EXCEPTION 'binding epoch snapshot is absent' USING ERRCODE='40001'; END IF;
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL THEN RAISE EXCEPTION 'binding apply requires participant entry' USING ERRCODE='42501'; END IF;
 IF proof->>'purpose' IS DISTINCT FROM 'participant' THEN RAISE EXCEPTION 'binding apply requires ordinary participant' USING ERRCODE='42501'; END IF;
 IF p_accounts IS NULL THEN
  IF proof->>'mode' IS DISTINCT FROM 'global' THEN RAISE EXCEPTION 'binding global epoch requires global entry' USING ERRCODE='42501'; END IF;
  PERFORM scope FROM kaname.authority_binding_epoch WHERE scope='' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'binding epochs are uninitialized' USING ERRCODE='40001'; END IF;
 ELSE
  IF pg_catalog.cardinality(p_accounts)=0 OR EXISTS(SELECT 1 FROM pg_catalog.unnest(p_accounts) a WHERE a IS NULL OR a='') THEN RAISE EXCEPTION 'invalid binding epoch scope'; END IF;
  IF proof->>'mode'='accounts' AND NOT (proof->'accounts') @> pg_catalog.to_jsonb(p_accounts) THEN RAISE EXCEPTION 'epoch accounts exceed participant scope' USING ERRCODE='42501'; END IF;
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
DROP TRIGGER authority_forward_anchor_complete_v4 ON kaname.authority_forward_emit_anchor_v4;
DROP FUNCTION kaname.authority_native_delete_emit_v4(jsonb[]);
DROP FUNCTION kaname.authority_native_delete_prepare_v4(jsonb[]);
DROP FUNCTION kaname.authority_native_delete_stamp_v4(uuid,bigint,jsonb);
DROP FUNCTION kaname.authority_forward_emit_v4(jsonb[]);
DROP FUNCTION kaname.authority_forward_prepare_v4(jsonb[]);
DROP FUNCTION kaname.authority_forward_claim_v4(uuid);
DROP FUNCTION kaname.authority_forward_finish_v4(uuid);
DROP FUNCTION kaname._authority_forward_custody_v4();
DROP FUNCTION kaname._authority_forward_shape_v4();
DROP FUNCTION kaname._authority_forward_context_v4();
DROP FUNCTION kaname._authority_forward_program_v4(uuid);
DROP FUNCTION kaname._authority_forward_row_v4(bigint,jsonb,boolean);
DROP FUNCTION kaname._authority_forward_complete_v4(uuid);
DROP FUNCTION kaname._authority_forward_anchor_complete_v4();
DROP FUNCTION kaname._authority_forward_storage_v4();
DROP TABLE kaname.authority_forward_emit_anchor_v4;
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
DROP FUNCTION kaname._authority_binding_mirror_before_write_v3(text,text,jsonb,jsonb);
DROP FUNCTION kaname._authority_binding_mirror_finalize_v3(text);
DROP FUNCTION kaname._authority_binding_mirror_prepare_v3(jsonb,integer,integer);
DROP FUNCTION kaname._authority_binding_mirror_epoch_v3(text[],jsonb,timestamptz);
DROP FUNCTION kaname._authority_audit_binding_store_v3();
DROP FUNCTION kaname._authority_binding_mirror_store_v3();
DROP FUNCTION kaname._authority_binding_mirror_locality_v3(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb);
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

DROP FUNCTION kaname._authority_group_add_storage_v3();
DROP FUNCTION kaname._authority_group_add_complete_v3();
DROP FUNCTION kaname._authority_group_add_subject_v3(text,text,jsonb);
DROP FUNCTION kaname.authority_group_add_subject_id_v3();
DROP FUNCTION kaname.authority_group_add_fold_v3(text,jsonb,timestamptz);
DROP FUNCTION kaname._authority_group_add_statement_v3(text,text);
DROP FUNCTION kaname._authority_group_add_row_v3(text,text,jsonb,jsonb);
DROP FUNCTION kaname.authority_group_add_finalize_v3(jsonb,integer,integer);
DROP FUNCTION kaname.authority_group_add_prepare_v3(jsonb,integer,integer);
DROP FUNCTION kaname._authority_group_add_program_v3();
