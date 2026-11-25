-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
LOCK TABLE kaname.authority_access_label_dirty_root,kaname.authority_access_label_dirty_fact IN ACCESS EXCLUSIVE MODE;
ALTER TABLE kaname.authority_access_label_dirty_root DROP CONSTRAINT authority_access_label_dirty_root_type;
ALTER TABLE kaname.authority_access_label_dirty_root ADD CONSTRAINT authority_access_label_dirty_root_type
 CHECK (root_type='iam.group' OR root_type='iam.user' OR kaname._authority_access_label_dirty_root_type_valid_v1(root_type));

-- +goose StatementBegin
DO $storage_contract$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
    ('_authority_access_label_object_generation_capture_v1(text,text,integer,integer)','5dfd98ff9eabebafdc94f2584fb9a80b8ea39dcd223b76497e495fbfcf5320b3','a42326162a99ba566ed1992209a43f81a9a464566f7aeffcc8716a293f1fdfac',
    jsonb_build_array(
      jsonb_build_array($part$WHEN 'iam_group' THEN 'iam.group' END;$part$,
       $part$WHEN 'iam_group' THEN 'iam.group' WHEN 'iam_user' THEN 'iam.user' END;$part$),
      jsonb_build_array($part$('cluster','iam_user','iam_role','iam_access_binding')$part$,
       $part$('cluster','iam_role','iam_access_binding')$part$)
    )),
    ('authority_resource_reconcile_pending_v1(text,text,integer,integer)','fb3f4cb89531f2b94ca68ed5ec6e604c484595b9ba1757c20d88f4236a49b024','83fdf25fd602ba09852eed3c74fd831128fa397cdcdb57a7b6c0d499ee1b750e',
    jsonb_build_array(
      jsonb_build_array($part$WHEN 'iam_group' THEN 'iam.group' END;$part$,
       $part$WHEN 'iam_group' THEN 'iam.group' WHEN 'iam_user' THEN 'iam.user' END;$part$),
      jsonb_build_array($part$('cluster','iam_user','iam_role','iam_access_binding')$part$,
       $part$('cluster','iam_role','iam_access_binding')$part$)
    )),
    ('_authority_access_label_generation_root_keys_v1(jsonb)','d401d36e3f917dedbdec49ba27e51821c17ea0e0a521cb1fc8cff4fef7ca9ab0','5b804b346bd94653d71ebc517e486413d3f4798cb05f7e7d0b48e84c3469e405',
    jsonb_build_array(
      jsonb_build_array($part$typ IS DISTINCT FROM 'iam.group' AND $part$,
       $part$typ IS DISTINCT FROM 'iam.group' AND typ IS DISTINCT FROM 'iam.user' AND $part$)
    )),
    ('_authority_access_label_generation_discharge_v1(jsonb,jsonb,jsonb,jsonb,timestamptz,integer)','34f60c48e3a6e6524482b989e0787c40403d59b48695fcfd95a74903c7c84260','6f72d3bd3eb0489280a1e3cd3aa5d323ca5ac73a051b63b7b7e7b9822c16c3e4',
    jsonb_build_array(
      jsonb_build_array($part$(root_row->>'root_type') IS DISTINCT FROM 'iam.group' AND $part$,
       $part$(root_row->>'root_type') IS DISTINCT FROM 'iam.group' AND (root_row->>'root_type') IS DISTINCT FROM 'iam.user' AND $part$)
    )),
    ('_authority_access_label_object_generation_finish_v1(jsonb,jsonb,integer,integer)','f6445458ff1427fae574a7dde7620462d55c1d95576129ab38fd2de92dbdb5a7','10c43e01d6e1b930ee4c574e47007ca7154b797ee0c3ede41f520c210ecf7b1b',
    jsonb_build_array(
      jsonb_build_array($part$v_root_type IS DISTINCT FROM 'iam.group' AND $part$,
       $part$v_root_type IS DISTINCT FROM 'iam.group' AND v_root_type IS DISTINCT FROM 'iam.user' AND $part$)
    )),
    ('_authority_access_label_generation_binding_read_hold_v1(jsonb,jsonb,jsonb,integer,integer,integer)','b337730a6575cc7426186949fdab6f4bcc35a7f6616efa5902b58bf108943b03','9dc26f010aaac554fd6a0d3aae5718c39504ebb85e07f2a5f6192e32b5db4bc3',
    jsonb_build_array(
      jsonb_build_array($part$'iam.serviceAccount','iam.group') THEN CONTINUE;$part$,
       $part$'iam.serviceAccount','iam.group','iam.user') THEN CONTINUE;$part$)
    )),
    ('_authority_access_label_generation_graphs_v1(jsonb,jsonb,jsonb,jsonb)','6e68a6ec865fee9afeaa80188179a24c88ce8df88a468a04dd487cf40f25ae1e','a39f5eb4c8c90be01955199ef980d50061ae05b39c9f0f9a17a5b26bc8e67bb6',
    jsonb_build_array(
      jsonb_build_array($part$WHEN dotted='iam.group' THEN model IS DISTINCT FROM 'iam_group'$part$,
       $part$WHEN dotted='iam.group' THEN model IS DISTINCT FROM 'iam_group'
    WHEN dotted='iam.user' THEN model IS DISTINCT FROM 'iam_user'$part$),
      jsonb_build_array($part$entry.lifecycle AND entry.dotted<>'iam.group'$part$,
       $part$entry.lifecycle AND entry.dotted NOT IN ('iam.group','iam.user')$part$),
      jsonb_build_array($part$  IF (p_certificate->'graphs') ? entry.key THEN$part$,
       $part$  IF entry.lifecycle AND entry.dotted='iam.user' THEN
   -- Только физический User с пустым предикатом членств требует глобальной
   -- ограды. K30 и K31 сверяются с текущими источниками до окончательных часов.
   work:=work+2;
   IF work>100000 THEN RAISE EXCEPTION 'user generation scope budget exceeded' USING ERRCODE='54000';END IF;
   lifecycle_source:=kaname._authority_resource_require_capture_v2(p_index,30,entry.dotted,entry.id);
   IF jsonb_array_length(lifecycle_source->'states') IS DISTINCT FROM 1
    OR lifecycle_source#>>'{states,0,2,id}' IS DISTINCT FROM entry.id THEN
    RAISE EXCEPTION 'user generation root missing' USING ERRCODE='42501';END IF;
   lifecycle_source:=kaname._authority_resource_require_capture_v2(p_index,31,entry.dotted,entry.id);
   IF lifecycle_source->'states'='[]'::jsonb THEN
    p_certificate:=jsonb_set(p_certificate,'{global}','true'::jsonb);
   END IF;
  END IF;
  IF (p_certificate->'graphs') ? entry.key THEN$part$)
    )),
    ('_authority_access_label_generation_lifecycle_plan_v1(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,integer,integer,integer)','0d5ac9c8cd03d40f17fd1d72a4581d2e3b3d7ba866d94808cd851f04027336e4','fa231c46554f5512731ad0dd2e082a3cadae5f3c4df3b58d8e4d742e3a55af9c',
    jsonb_build_array(
      jsonb_build_array($part$DECLARE checked_group_sources boolean:=false;$part$,
       $part$DECLARE checked_user_sources boolean:=false;checked_group_sources boolean:=false;$part$),
      jsonb_build_array($part$CASE WHEN dotted='iam.group' THEN ARRAY[30] ELSE$part$,
       $part$CASE WHEN dotted='iam.group' THEN ARRAY[30] WHEN dotted='iam.user' THEN ARRAY[30,31] ELSE$part$),
      jsonb_build_array($part$CASE WHEN kind IN (2,30) THEN dotted$part$,
       $part$CASE WHEN kind IN (2,30,31) THEN dotted$part$),
      jsonb_build_array($part$  required:='{}'::jsonb;predicates:='{}'::jsonb;$part$,
       $part$  IF dotted='iam.user' THEN
   -- K31 может быть пуст: row locks защищают только уже существующие строки.
   -- Общая и персональная policy epoch сериализуют изменение предиката с finish.
   used_rows:=used_rows+2;used_reads:=used_reads+2;
   IF NOT checked_user_sources THEN
    used_rows:=used_rows+10;used_reads:=used_reads+3;
   END IF;
   IF used_rows>p_rows OR used_reads>p_reads THEN
    RAISE EXCEPTION 'user generation predicate hold exceeds budget' USING ERRCODE='54000';END IF;
   BEGIN
   IF NOT checked_user_sources THEN
    LOCK TABLE ONLY kaname.memberships IN ROW EXCLUSIVE MODE NOWAIT;
    IF current_setting('session_replication_role') NOT IN ('origin','local') OR
     (SELECT count(*) FROM pg_catalog.pg_class c
      WHERE c.oid IN ('kaname.users'::regclass,'kaname.memberships'::regclass,
                      'kaname.accounts'::regclass,'kaname.catalog_resource'::regclass)
       AND c.relkind='r' AND c.relpersistence='p' AND NOT (c.relrowsecurity OR c.relforcerowsecurity
          OR c.relhasrules OR c.relispartition OR c.relhassubclass)
       AND NOT EXISTS(SELECT FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid))<>4 THEN
     RAISE EXCEPTION 'user generation native source differs' USING ERRCODE='42501';END IF;
    IF EXISTS(SELECT FROM (VALUES
        ('policy_epoch_insert',4,NULL,'new_policy_rows'),('policy_epoch_update',16,'old_policy_rows','new_policy_rows'),
        ('policy_epoch_delete',8,'old_policy_rows',NULL),('policy_epoch_truncate',32,NULL,NULL)
    ) expected(name,kind,olds,news) WHERE NOT EXISTS(
        SELECT FROM pg_catalog.pg_trigger t WHERE t.tgrelid='kaname.memberships'::regclass
        AND t.tgname=expected.name AND t.tgfoid='kaname.authority_policy_changed()'::regprocedure
        AND t.tgtype=expected.kind AND t.tgenabled IN ('A','O') AND NOT t.tgisinternal
        AND t.tgconstraint=0 AND NOT t.tgdeferrable AND NOT t.tginitdeferred
        AND t.tgnargs=0 AND t.tgattr::text='' AND t.tgqual IS NULL
        AND t.tgoldtable::text IS NOT DISTINCT FROM expected.olds AND t.tgnewtable::text IS NOT DISTINCT FROM expected.news
    )) OR EXISTS(SELECT FROM (VALUES
        ('kaname.authority_policy_changed()','46a479262309d1ab8cd6efd41ea519921eb57c13ca7b5054ce6550aba366371d'),
        ('kaname.authority_policy_keys(text,jsonb)','5bed24d2efa4e9dd3eadd3224d06031b5eeebf6785e7461ece8a4830adb46e86')
    ) expected(signature,digest) WHERE NOT EXISTS(
        SELECT FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure(expected.signature)
        AND p.proowner=current_user::regrole AND p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
        AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=expected.digest
    )) THEN
        RAISE EXCEPTION 'user membership policy epoch producer differs' USING ERRCODE='42501';
    END IF;
    checked_user_sources:=true;
   END IF;
   PERFORM FROM ONLY kaname.authority_policy_epoch WHERE key='*' FOR SHARE NOWAIT;
   IF NOT FOUND THEN RAISE EXCEPTION 'user generation global epoch absent' USING ERRCODE='40001';END IF;
   PERFORM FROM ONLY kaname.authority_policy_epoch WHERE key='user:'||identifier FOR SHARE NOWAIT;
   IF NOT FOUND THEN RAISE EXCEPTION 'user generation policy epoch absent' USING ERRCODE='40001';END IF;
   EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'user generation membership predicate is changing' USING ERRCODE='40001';
   END;
  END IF;
  required:='{}'::jsonb;predicates:='{}'::jsonb;$part$),
      jsonb_build_array($part$    IF dotted='iam.group' AND (kind NOT IN (23,30)$part$,
       $part$    IF dotted='iam.user' THEN
     work:=work+1+jsonb_array_length(p_current->entry.key);
     IF work>p_work THEN RAISE EXCEPTION 'user generation relation check exceeds budget' USING ERRCODE='54000';END IF;
    END IF;
    IF dotted='iam.user' AND (kind NOT IN (23,30,31)
      OR (kind IN (23,30) AND jsonb_array_length(p_current->entry.key)<>1)
      OR EXISTS(SELECT FROM jsonb_array_elements(p_current->entry.key) v WHERE v->>'relation' IS DISTINCT FROM
          (CASE kind WHEN 23 THEN 'kaname.accounts'::regclass WHEN 30 THEN 'kaname.users'::regclass
                     WHEN 31 THEN 'kaname.memberships'::regclass END)::oid::text)) THEN
     RAISE EXCEPTION 'user generation native held relation differs' USING ERRCODE='42501';END IF;
    IF dotted='iam.group' AND (kind NOT IN (23,30)$part$)
    )),
    ('_authority_access_label_generation_lifecycle_validate_v1(jsonb,jsonb)','5a6b46449f1f93880e2de0d4ce0efedeb89cf3613e3673fe62a8b0530ceb842f','a8a42b0fd7fdf88d5b0ad25e8dadee68bdaa8a10c238ed1f6fdb6dd69b830af5',
    jsonb_build_array(
      jsonb_build_array($part$dotted IS DISTINCT FROM 'iam.group' AND (kaname.$part$,
       $part$dotted IS DISTINCT FROM 'iam.group' AND dotted IS DISTINCT FROM 'iam.user' AND (kaname.$part$),
      jsonb_build_array($part$CASE WHEN dotted='iam.group' THEN ARRAY[30] ELSE$part$,
       $part$CASE WHEN dotted='iam.group' THEN ARRAY[30] WHEN dotted='iam.user' THEN ARRAY[30,31] ELSE$part$),
      jsonb_build_array($part$CASE WHEN kind IN (2,30) THEN dotted$part$,
       $part$CASE WHEN kind IN (2,30,31) THEN dotted$part$),
      jsonb_build_array($part$ IF dotted='iam.group' AND ($part$,
       $part$ IF dotted='iam.user' AND (model IS DISTINCT FROM 'iam_user' OR coalesce(identifier,'') COLLATE "C" !~ '^usr[a-zA-Z0-9_-]{1,61}$'
  OR raw->>'module' IS DISTINCT FROM 'iam' OR raw->>'resource' IS DISTINCT FROM 'user'
  OR raw->'live' IS DISTINCT FROM 'true'::jsonb OR p_lifecycle->'present' IS DISTINCT FROM 'true'::jsonb
  OR p_lifecycle->'projects' IS DISTINCT FROM '{}'::jsonb) THEN
  RAISE EXCEPTION 'user generation requires a live native user' USING ERRCODE='42501';END IF;
 IF dotted='iam.group' AND ($part$),
      jsonb_build_array($part$OR (kind NOT IN (1,23,30) AND (raw->>'object_type'$part$,
       $part$OR (kind=31 AND (raw->>'user_id' IS DISTINCT FROM identifier
       OR coalesce(raw->>'account_id','') COLLATE "C" !~ '^acc[a-zA-Z0-9_-]{1,61}$'))
   OR (kind NOT IN (1,23,30,31) AND (raw->>'object_type'$part$),
      jsonb_build_array($part$ IF dotted='iam.group' THEN
  source_key:=$part$,
       $part$ IF dotted='iam.user' THEN
  raw:=p_lifecycle->'predicates'->(jsonb_build_array(30,dotted,identifier,'')::text)->0->2;
  source_key:=jsonb_build_array(31,dotted,identifier,'')::text;
  SELECT coalesce(jsonb_object_agg(m#>>'{2,account_id}',true),'{}'::jsonb)
   INTO scopes FROM jsonb_array_elements(p_lifecycle->'predicates'->source_key) m;
  IF raw->'access_labels' IS DISTINCT FROM p_root_state#>'{2,new_labels}'
   OR kaname.access_labels_valid_v1(raw->'access_labels') IS DISTINCT FROM true
   OR scopes IS DISTINCT FROM p_lifecycle->'accounts'
   OR (SELECT count(*) FROM jsonb_object_keys(scopes))<>jsonb_array_length(p_lifecycle->'predicates'->source_key) THEN
   RAISE EXCEPTION 'user generation held memberships or labels differ' USING ERRCODE='42501';END IF;
  -- Второй проход K31 для точного набора аккаунтов, включая пустой набор.
  RETURN jsonb_build_object('rows',rows_count,'reads',reads_count,
   'work',work+jsonb_array_length(p_lifecycle->'predicates'->source_key));
 END IF;
 IF dotted='iam.group' THEN
  source_key:=$part$)
    )),
    ('_authority_access_label_generation_lifecycle_finish_v1(jsonb,jsonb,integer,integer)','c4ce49701c047a9b4bb14b1a0ed218ec794b41f493a8c9104275c6335b05296e','6f629cf14fffaaea6dc5d76f2a584d42ca0225bc2e4e4321fba0dfdba6feb151',
    jsonb_build_array(
      jsonb_build_array($part$WHEN 30 THEN table_name:='groups';$part$,
       $part$WHEN 30 THEN table_name:=CASE dotted WHEN 'iam.user' THEN 'users' ELSE 'groups' END;
   WHEN 31 THEN table_name:='memberships';$part$),
      jsonb_build_array($part$THEN 'r.id=$2' ELSE 'r.object_type=$1 AND r.object_id=$2' END;$part$,
       $part$THEN 'r.id=$2' WHEN (k->>0)::integer=31 THEN 'r.user_id=$2' ELSE 'r.object_type=$1 AND r.object_id=$2' END;$part$)
    )),
    ('_authority_access_label_freshness_storage_v1()','3d124bbd2209903ee01236e8d402d2773e964fb9de79ca39171dda88e0b4ef87','2ae2a6ff97608b798e664995ac982845de380d936cee83815eaa0eb86569227b',
    jsonb_build_array(
      jsonb_build_array($part$root_type=''iam.group''::textORkaname._authority_access_label_dirty_root_type_valid_v1root_type$part$,
       $part$root_type=''iam.group''::textORroot_type=''iam.user''::textORkaname._authority_access_label_dirty_root_type_valid_v1root_type$part$)
    )),
    ('_authority_crud_storage_v3()','e5250e124e4648060903596c2291de971d58159b416cd6a80428bf9885fce5b2','062e05901521412fe88a90ae49d1d6d6a9a8bbf543b6db5cf60ecbecc321232e',
    jsonb_build_array(
      jsonb_build_array($part$5dfd98ff9eabebafdc94f2584fb9a80b8ea39dcd223b76497e495fbfcf5320b3$part$,
       $part$a42326162a99ba566ed1992209a43f81a9a464566f7aeffcc8716a293f1fdfac$part$),
      jsonb_build_array($part$d401d36e3f917dedbdec49ba27e51821c17ea0e0a521cb1fc8cff4fef7ca9ab0$part$,
       $part$5b804b346bd94653d71ebc517e486413d3f4798cb05f7e7d0b48e84c3469e405$part$),
      jsonb_build_array($part$34f60c48e3a6e6524482b989e0787c40403d59b48695fcfd95a74903c7c84260$part$,
       $part$6f72d3bd3eb0489280a1e3cd3aa5d323ca5ac73a051b63b7b7e7b9822c16c3e4$part$),
      jsonb_build_array($part$f6445458ff1427fae574a7dde7620462d55c1d95576129ab38fd2de92dbdb5a7$part$,
       $part$10c43e01d6e1b930ee4c574e47007ca7154b797ee0c3ede41f520c210ecf7b1b$part$),
      jsonb_build_array($part$b337730a6575cc7426186949fdab6f4bcc35a7f6616efa5902b58bf108943b03$part$,
       $part$9dc26f010aaac554fd6a0d3aae5718c39504ebb85e07f2a5f6192e32b5db4bc3$part$),
      jsonb_build_array($part$6e68a6ec865fee9afeaa80188179a24c88ce8df88a468a04dd487cf40f25ae1e$part$,
       $part$a39f5eb4c8c90be01955199ef980d50061ae05b39c9f0f9a17a5b26bc8e67bb6$part$),
      jsonb_build_array($part$0d5ac9c8cd03d40f17fd1d72a4581d2e3b3d7ba866d94808cd851f04027336e4$part$,
       $part$fa231c46554f5512731ad0dd2e082a3cadae5f3c4df3b58d8e4d742e3a55af9c$part$),
      jsonb_build_array($part$5a6b46449f1f93880e2de0d4ce0efedeb89cf3613e3673fe62a8b0530ceb842f$part$,
       $part$a8a42b0fd7fdf88d5b0ad25e8dadee68bdaa8a10c238ed1f6fdb6dd69b830af5$part$),
      jsonb_build_array($part$c4ce49701c047a9b4bb14b1a0ed218ec794b41f493a8c9104275c6335b05296e$part$,
       $part$6f629cf14fffaaea6dc5d76f2a584d42ca0225bc2e4e4321fba0dfdba6feb151$part$)
    )),
    ('_authority_full_contract_storage_v3()','7e9ef290479a7ab33c091251069ae2a63684c19094104180131808c1c81fe381','47b4241863863490367dc274ce447fd24f25eb0b98f19f35d6551b9ac554a2c0',
    jsonb_build_array(
      jsonb_build_array($part$3d124bbd2209903ee01236e8d402d2773e964fb9de79ca39171dda88e0b4ef87$part$,
       $part$2ae2a6ff97608b798e664995ac982845de380d936cee83815eaa0eb86569227b$part$),
      jsonb_build_array($part$e5250e124e4648060903596c2291de971d58159b416cd6a80428bf9885fce5b2$part$,
       $part$062e05901521412fe88a90ae49d1d6d6a9a8bbf543b6db5cf60ecbecc321232e$part$)
    )),
    ('authority_metadata_service_account_access_label_ready_v1()','91b537ba372c6510936664ff6ee7c58d4ee608a7963723461544cf97379cb9e2','b1a32f4007d0f2c2d2b87f1de8f95d9ac6d9008a32437d5339b2bd0e34bc9843',
    jsonb_build_array(
      jsonb_build_array($part$5dfd98ff9eabebafdc94f2584fb9a80b8ea39dcd223b76497e495fbfcf5320b3$part$,
       $part$a42326162a99ba566ed1992209a43f81a9a464566f7aeffcc8716a293f1fdfac$part$),
      jsonb_build_array($part$fb3f4cb89531f2b94ca68ed5ec6e604c484595b9ba1757c20d88f4236a49b024$part$,
       $part$83fdf25fd602ba09852eed3c74fd831128fa397cdcdb57a7b6c0d499ee1b750e$part$),
      jsonb_build_array($part$d401d36e3f917dedbdec49ba27e51821c17ea0e0a521cb1fc8cff4fef7ca9ab0$part$,
       $part$5b804b346bd94653d71ebc517e486413d3f4798cb05f7e7d0b48e84c3469e405$part$),
      jsonb_build_array($part$34f60c48e3a6e6524482b989e0787c40403d59b48695fcfd95a74903c7c84260$part$,
       $part$6f72d3bd3eb0489280a1e3cd3aa5d323ca5ac73a051b63b7b7e7b9822c16c3e4$part$),
      jsonb_build_array($part$f6445458ff1427fae574a7dde7620462d55c1d95576129ab38fd2de92dbdb5a7$part$,
       $part$10c43e01d6e1b930ee4c574e47007ca7154b797ee0c3ede41f520c210ecf7b1b$part$),
      jsonb_build_array($part$3d124bbd2209903ee01236e8d402d2773e964fb9de79ca39171dda88e0b4ef87$part$,
       $part$2ae2a6ff97608b798e664995ac982845de380d936cee83815eaa0eb86569227b$part$),
      jsonb_build_array($part$e5250e124e4648060903596c2291de971d58159b416cd6a80428bf9885fce5b2$part$,
       $part$062e05901521412fe88a90ae49d1d6d6a9a8bbf543b6db5cf60ecbecc321232e$part$),
      jsonb_build_array($part$7e9ef290479a7ab33c091251069ae2a63684c19094104180131808c1c81fe381$part$,
       $part$47b4241863863490367dc274ce447fd24f25eb0b98f19f35d6551b9ac554a2c0$part$)
    ))
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'user generation worker contract predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'user generation worker contract replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'user generation worker contract body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'user generation worker contract installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_access_label_freshness_storage_v1() IS DISTINCT FROM true
        OR kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'user generation worker contract storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage_contract$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
LOCK TABLE kaname.authority_access_label_dirty_root,kaname.authority_access_label_dirty_fact IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $roots$
BEGIN
 IF EXISTS(SELECT FROM ONLY kaname.authority_access_label_dirty_root WHERE root_type='iam.user') THEN
  RAISE EXCEPTION 'finish pending user generations before rollback' USING ERRCODE='55000';END IF;
END;
$roots$;
-- +goose StatementEnd
ALTER TABLE kaname.authority_access_label_dirty_root DROP CONSTRAINT authority_access_label_dirty_root_type;
ALTER TABLE kaname.authority_access_label_dirty_root ADD CONSTRAINT authority_access_label_dirty_root_type
 CHECK (root_type='iam.group' OR kaname._authority_access_label_dirty_root_type_valid_v1(root_type));

-- +goose StatementBegin
DO $storage_contract$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
    ('authority_metadata_service_account_access_label_ready_v1()','b1a32f4007d0f2c2d2b87f1de8f95d9ac6d9008a32437d5339b2bd0e34bc9843','91b537ba372c6510936664ff6ee7c58d4ee608a7963723461544cf97379cb9e2',
    jsonb_build_array(
      jsonb_build_array($part$47b4241863863490367dc274ce447fd24f25eb0b98f19f35d6551b9ac554a2c0$part$,
       $part$7e9ef290479a7ab33c091251069ae2a63684c19094104180131808c1c81fe381$part$),
      jsonb_build_array($part$062e05901521412fe88a90ae49d1d6d6a9a8bbf543b6db5cf60ecbecc321232e$part$,
       $part$e5250e124e4648060903596c2291de971d58159b416cd6a80428bf9885fce5b2$part$),
      jsonb_build_array($part$2ae2a6ff97608b798e664995ac982845de380d936cee83815eaa0eb86569227b$part$,
       $part$3d124bbd2209903ee01236e8d402d2773e964fb9de79ca39171dda88e0b4ef87$part$),
      jsonb_build_array($part$10c43e01d6e1b930ee4c574e47007ca7154b797ee0c3ede41f520c210ecf7b1b$part$,
       $part$f6445458ff1427fae574a7dde7620462d55c1d95576129ab38fd2de92dbdb5a7$part$),
      jsonb_build_array($part$6f72d3bd3eb0489280a1e3cd3aa5d323ca5ac73a051b63b7b7e7b9822c16c3e4$part$,
       $part$34f60c48e3a6e6524482b989e0787c40403d59b48695fcfd95a74903c7c84260$part$),
      jsonb_build_array($part$5b804b346bd94653d71ebc517e486413d3f4798cb05f7e7d0b48e84c3469e405$part$,
       $part$d401d36e3f917dedbdec49ba27e51821c17ea0e0a521cb1fc8cff4fef7ca9ab0$part$),
      jsonb_build_array($part$83fdf25fd602ba09852eed3c74fd831128fa397cdcdb57a7b6c0d499ee1b750e$part$,
       $part$fb3f4cb89531f2b94ca68ed5ec6e604c484595b9ba1757c20d88f4236a49b024$part$),
      jsonb_build_array($part$a42326162a99ba566ed1992209a43f81a9a464566f7aeffcc8716a293f1fdfac$part$,
       $part$5dfd98ff9eabebafdc94f2584fb9a80b8ea39dcd223b76497e495fbfcf5320b3$part$)
    )),
    ('_authority_full_contract_storage_v3()','47b4241863863490367dc274ce447fd24f25eb0b98f19f35d6551b9ac554a2c0','7e9ef290479a7ab33c091251069ae2a63684c19094104180131808c1c81fe381',
    jsonb_build_array(
      jsonb_build_array($part$062e05901521412fe88a90ae49d1d6d6a9a8bbf543b6db5cf60ecbecc321232e$part$,
       $part$e5250e124e4648060903596c2291de971d58159b416cd6a80428bf9885fce5b2$part$),
      jsonb_build_array($part$2ae2a6ff97608b798e664995ac982845de380d936cee83815eaa0eb86569227b$part$,
       $part$3d124bbd2209903ee01236e8d402d2773e964fb9de79ca39171dda88e0b4ef87$part$)
    )),
    ('_authority_crud_storage_v3()','062e05901521412fe88a90ae49d1d6d6a9a8bbf543b6db5cf60ecbecc321232e','e5250e124e4648060903596c2291de971d58159b416cd6a80428bf9885fce5b2',
    jsonb_build_array(
      jsonb_build_array($part$6f629cf14fffaaea6dc5d76f2a584d42ca0225bc2e4e4321fba0dfdba6feb151$part$,
       $part$c4ce49701c047a9b4bb14b1a0ed218ec794b41f493a8c9104275c6335b05296e$part$),
      jsonb_build_array($part$a8a42b0fd7fdf88d5b0ad25e8dadee68bdaa8a10c238ed1f6fdb6dd69b830af5$part$,
       $part$5a6b46449f1f93880e2de0d4ce0efedeb89cf3613e3673fe62a8b0530ceb842f$part$),
      jsonb_build_array($part$fa231c46554f5512731ad0dd2e082a3cadae5f3c4df3b58d8e4d742e3a55af9c$part$,
       $part$0d5ac9c8cd03d40f17fd1d72a4581d2e3b3d7ba866d94808cd851f04027336e4$part$),
      jsonb_build_array($part$a39f5eb4c8c90be01955199ef980d50061ae05b39c9f0f9a17a5b26bc8e67bb6$part$,
       $part$6e68a6ec865fee9afeaa80188179a24c88ce8df88a468a04dd487cf40f25ae1e$part$),
      jsonb_build_array($part$9dc26f010aaac554fd6a0d3aae5718c39504ebb85e07f2a5f6192e32b5db4bc3$part$,
       $part$b337730a6575cc7426186949fdab6f4bcc35a7f6616efa5902b58bf108943b03$part$),
      jsonb_build_array($part$10c43e01d6e1b930ee4c574e47007ca7154b797ee0c3ede41f520c210ecf7b1b$part$,
       $part$f6445458ff1427fae574a7dde7620462d55c1d95576129ab38fd2de92dbdb5a7$part$),
      jsonb_build_array($part$6f72d3bd3eb0489280a1e3cd3aa5d323ca5ac73a051b63b7b7e7b9822c16c3e4$part$,
       $part$34f60c48e3a6e6524482b989e0787c40403d59b48695fcfd95a74903c7c84260$part$),
      jsonb_build_array($part$5b804b346bd94653d71ebc517e486413d3f4798cb05f7e7d0b48e84c3469e405$part$,
       $part$d401d36e3f917dedbdec49ba27e51821c17ea0e0a521cb1fc8cff4fef7ca9ab0$part$),
      jsonb_build_array($part$a42326162a99ba566ed1992209a43f81a9a464566f7aeffcc8716a293f1fdfac$part$,
       $part$5dfd98ff9eabebafdc94f2584fb9a80b8ea39dcd223b76497e495fbfcf5320b3$part$)
    )),
    ('_authority_access_label_freshness_storage_v1()','2ae2a6ff97608b798e664995ac982845de380d936cee83815eaa0eb86569227b','3d124bbd2209903ee01236e8d402d2773e964fb9de79ca39171dda88e0b4ef87',
    jsonb_build_array(
      jsonb_build_array($part$root_type=''iam.group''::textORroot_type=''iam.user''::textORkaname._authority_access_label_dirty_root_type_valid_v1root_type$part$,
       $part$root_type=''iam.group''::textORkaname._authority_access_label_dirty_root_type_valid_v1root_type$part$)
    )),
    ('_authority_access_label_generation_lifecycle_finish_v1(jsonb,jsonb,integer,integer)','6f629cf14fffaaea6dc5d76f2a584d42ca0225bc2e4e4321fba0dfdba6feb151','c4ce49701c047a9b4bb14b1a0ed218ec794b41f493a8c9104275c6335b05296e',
    jsonb_build_array(
      jsonb_build_array($part$THEN 'r.id=$2' WHEN (k->>0)::integer=31 THEN 'r.user_id=$2' ELSE 'r.object_type=$1 AND r.object_id=$2' END;$part$,
       $part$THEN 'r.id=$2' ELSE 'r.object_type=$1 AND r.object_id=$2' END;$part$),
      jsonb_build_array($part$WHEN 30 THEN table_name:=CASE dotted WHEN 'iam.user' THEN 'users' ELSE 'groups' END;
   WHEN 31 THEN table_name:='memberships';$part$,
       $part$WHEN 30 THEN table_name:='groups';$part$)
    )),
    ('_authority_access_label_generation_lifecycle_validate_v1(jsonb,jsonb)','a8a42b0fd7fdf88d5b0ad25e8dadee68bdaa8a10c238ed1f6fdb6dd69b830af5','5a6b46449f1f93880e2de0d4ce0efedeb89cf3613e3673fe62a8b0530ceb842f',
    jsonb_build_array(
      jsonb_build_array($part$ IF dotted='iam.user' THEN
  raw:=p_lifecycle->'predicates'->(jsonb_build_array(30,dotted,identifier,'')::text)->0->2;
  source_key:=jsonb_build_array(31,dotted,identifier,'')::text;
  SELECT coalesce(jsonb_object_agg(m#>>'{2,account_id}',true),'{}'::jsonb)
   INTO scopes FROM jsonb_array_elements(p_lifecycle->'predicates'->source_key) m;
  IF raw->'access_labels' IS DISTINCT FROM p_root_state#>'{2,new_labels}'
   OR kaname.access_labels_valid_v1(raw->'access_labels') IS DISTINCT FROM true
   OR scopes IS DISTINCT FROM p_lifecycle->'accounts'
   OR (SELECT count(*) FROM jsonb_object_keys(scopes))<>jsonb_array_length(p_lifecycle->'predicates'->source_key) THEN
   RAISE EXCEPTION 'user generation held memberships or labels differ' USING ERRCODE='42501';END IF;
  -- Второй проход K31 для точного набора аккаунтов, включая пустой набор.
  RETURN jsonb_build_object('rows',rows_count,'reads',reads_count,
   'work',work+jsonb_array_length(p_lifecycle->'predicates'->source_key));
 END IF;
 IF dotted='iam.group' THEN
  source_key:=$part$,
       $part$ IF dotted='iam.group' THEN
  source_key:=$part$),
      jsonb_build_array($part$OR (kind=31 AND (raw->>'user_id' IS DISTINCT FROM identifier
       OR coalesce(raw->>'account_id','') COLLATE "C" !~ '^acc[a-zA-Z0-9_-]{1,61}$'))
   OR (kind NOT IN (1,23,30,31) AND (raw->>'object_type'$part$,
       $part$OR (kind NOT IN (1,23,30) AND (raw->>'object_type'$part$),
      jsonb_build_array($part$ IF dotted='iam.user' AND (model IS DISTINCT FROM 'iam_user' OR coalesce(identifier,'') COLLATE "C" !~ '^usr[a-zA-Z0-9_-]{1,61}$'
  OR raw->>'module' IS DISTINCT FROM 'iam' OR raw->>'resource' IS DISTINCT FROM 'user'
  OR raw->'live' IS DISTINCT FROM 'true'::jsonb OR p_lifecycle->'present' IS DISTINCT FROM 'true'::jsonb
  OR p_lifecycle->'projects' IS DISTINCT FROM '{}'::jsonb) THEN
  RAISE EXCEPTION 'user generation requires a live native user' USING ERRCODE='42501';END IF;
 IF dotted='iam.group' AND ($part$,
       $part$ IF dotted='iam.group' AND ($part$),
      jsonb_build_array($part$CASE WHEN kind IN (2,30,31) THEN dotted$part$,
       $part$CASE WHEN kind IN (2,30) THEN dotted$part$),
      jsonb_build_array($part$CASE WHEN dotted='iam.group' THEN ARRAY[30] WHEN dotted='iam.user' THEN ARRAY[30,31] ELSE$part$,
       $part$CASE WHEN dotted='iam.group' THEN ARRAY[30] ELSE$part$),
      jsonb_build_array($part$dotted IS DISTINCT FROM 'iam.group' AND dotted IS DISTINCT FROM 'iam.user' AND (kaname.$part$,
       $part$dotted IS DISTINCT FROM 'iam.group' AND (kaname.$part$)
    )),
    ('_authority_access_label_generation_lifecycle_plan_v1(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,integer,integer,integer)','fa231c46554f5512731ad0dd2e082a3cadae5f3c4df3b58d8e4d742e3a55af9c','0d5ac9c8cd03d40f17fd1d72a4581d2e3b3d7ba866d94808cd851f04027336e4',
    jsonb_build_array(
      jsonb_build_array($part$    IF dotted='iam.user' THEN
     work:=work+1+jsonb_array_length(p_current->entry.key);
     IF work>p_work THEN RAISE EXCEPTION 'user generation relation check exceeds budget' USING ERRCODE='54000';END IF;
    END IF;
    IF dotted='iam.user' AND (kind NOT IN (23,30,31)
      OR (kind IN (23,30) AND jsonb_array_length(p_current->entry.key)<>1)
      OR EXISTS(SELECT FROM jsonb_array_elements(p_current->entry.key) v WHERE v->>'relation' IS DISTINCT FROM
          (CASE kind WHEN 23 THEN 'kaname.accounts'::regclass WHEN 30 THEN 'kaname.users'::regclass
                     WHEN 31 THEN 'kaname.memberships'::regclass END)::oid::text)) THEN
     RAISE EXCEPTION 'user generation native held relation differs' USING ERRCODE='42501';END IF;
    IF dotted='iam.group' AND (kind NOT IN (23,30)$part$,
       $part$    IF dotted='iam.group' AND (kind NOT IN (23,30)$part$),
      jsonb_build_array($part$  IF dotted='iam.user' THEN
   -- K31 может быть пуст: row locks защищают только уже существующие строки.
   -- Общая и персональная policy epoch сериализуют изменение предиката с finish.
   used_rows:=used_rows+2;used_reads:=used_reads+2;
   IF NOT checked_user_sources THEN
    used_rows:=used_rows+10;used_reads:=used_reads+3;
   END IF;
   IF used_rows>p_rows OR used_reads>p_reads THEN
    RAISE EXCEPTION 'user generation predicate hold exceeds budget' USING ERRCODE='54000';END IF;
   BEGIN
   IF NOT checked_user_sources THEN
    LOCK TABLE ONLY kaname.memberships IN ROW EXCLUSIVE MODE NOWAIT;
    IF current_setting('session_replication_role') NOT IN ('origin','local') OR
     (SELECT count(*) FROM pg_catalog.pg_class c
      WHERE c.oid IN ('kaname.users'::regclass,'kaname.memberships'::regclass,
                      'kaname.accounts'::regclass,'kaname.catalog_resource'::regclass)
       AND c.relkind='r' AND c.relpersistence='p' AND NOT (c.relrowsecurity OR c.relforcerowsecurity
          OR c.relhasrules OR c.relispartition OR c.relhassubclass)
       AND NOT EXISTS(SELECT FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid))<>4 THEN
     RAISE EXCEPTION 'user generation native source differs' USING ERRCODE='42501';END IF;
    IF EXISTS(SELECT FROM (VALUES
        ('policy_epoch_insert',4,NULL,'new_policy_rows'),('policy_epoch_update',16,'old_policy_rows','new_policy_rows'),
        ('policy_epoch_delete',8,'old_policy_rows',NULL),('policy_epoch_truncate',32,NULL,NULL)
    ) expected(name,kind,olds,news) WHERE NOT EXISTS(
        SELECT FROM pg_catalog.pg_trigger t WHERE t.tgrelid='kaname.memberships'::regclass
        AND t.tgname=expected.name AND t.tgfoid='kaname.authority_policy_changed()'::regprocedure
        AND t.tgtype=expected.kind AND t.tgenabled IN ('A','O') AND NOT t.tgisinternal
        AND t.tgconstraint=0 AND NOT t.tgdeferrable AND NOT t.tginitdeferred
        AND t.tgnargs=0 AND t.tgattr::text='' AND t.tgqual IS NULL
        AND t.tgoldtable::text IS NOT DISTINCT FROM expected.olds AND t.tgnewtable::text IS NOT DISTINCT FROM expected.news
    )) OR EXISTS(SELECT FROM (VALUES
        ('kaname.authority_policy_changed()','46a479262309d1ab8cd6efd41ea519921eb57c13ca7b5054ce6550aba366371d'),
        ('kaname.authority_policy_keys(text,jsonb)','5bed24d2efa4e9dd3eadd3224d06031b5eeebf6785e7461ece8a4830adb46e86')
    ) expected(signature,digest) WHERE NOT EXISTS(
        SELECT FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure(expected.signature)
        AND p.proowner=current_user::regrole AND p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
        AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=expected.digest
    )) THEN
        RAISE EXCEPTION 'user membership policy epoch producer differs' USING ERRCODE='42501';
    END IF;
    checked_user_sources:=true;
   END IF;
   PERFORM FROM ONLY kaname.authority_policy_epoch WHERE key='*' FOR SHARE NOWAIT;
   IF NOT FOUND THEN RAISE EXCEPTION 'user generation global epoch absent' USING ERRCODE='40001';END IF;
   PERFORM FROM ONLY kaname.authority_policy_epoch WHERE key='user:'||identifier FOR SHARE NOWAIT;
   IF NOT FOUND THEN RAISE EXCEPTION 'user generation policy epoch absent' USING ERRCODE='40001';END IF;
   EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'user generation membership predicate is changing' USING ERRCODE='40001';
   END;
  END IF;
  required:='{}'::jsonb;predicates:='{}'::jsonb;$part$,
       $part$  required:='{}'::jsonb;predicates:='{}'::jsonb;$part$),
      jsonb_build_array($part$CASE WHEN kind IN (2,30,31) THEN dotted$part$,
       $part$CASE WHEN kind IN (2,30) THEN dotted$part$),
      jsonb_build_array($part$CASE WHEN dotted='iam.group' THEN ARRAY[30] WHEN dotted='iam.user' THEN ARRAY[30,31] ELSE$part$,
       $part$CASE WHEN dotted='iam.group' THEN ARRAY[30] ELSE$part$),
      jsonb_build_array($part$DECLARE checked_user_sources boolean:=false;checked_group_sources boolean:=false;$part$,
       $part$DECLARE checked_group_sources boolean:=false;$part$)
    )),
    ('_authority_access_label_generation_graphs_v1(jsonb,jsonb,jsonb,jsonb)','a39f5eb4c8c90be01955199ef980d50061ae05b39c9f0f9a17a5b26bc8e67bb6','6e68a6ec865fee9afeaa80188179a24c88ce8df88a468a04dd487cf40f25ae1e',
    jsonb_build_array(
      jsonb_build_array($part$  IF entry.lifecycle AND entry.dotted='iam.user' THEN
   -- Только физический User с пустым предикатом членств требует глобальной
   -- ограды. K30 и K31 сверяются с текущими источниками до окончательных часов.
   work:=work+2;
   IF work>100000 THEN RAISE EXCEPTION 'user generation scope budget exceeded' USING ERRCODE='54000';END IF;
   lifecycle_source:=kaname._authority_resource_require_capture_v2(p_index,30,entry.dotted,entry.id);
   IF jsonb_array_length(lifecycle_source->'states') IS DISTINCT FROM 1
    OR lifecycle_source#>>'{states,0,2,id}' IS DISTINCT FROM entry.id THEN
    RAISE EXCEPTION 'user generation root missing' USING ERRCODE='42501';END IF;
   lifecycle_source:=kaname._authority_resource_require_capture_v2(p_index,31,entry.dotted,entry.id);
   IF lifecycle_source->'states'='[]'::jsonb THEN
    p_certificate:=jsonb_set(p_certificate,'{global}','true'::jsonb);
   END IF;
  END IF;
  IF (p_certificate->'graphs') ? entry.key THEN$part$,
       $part$  IF (p_certificate->'graphs') ? entry.key THEN$part$),
      jsonb_build_array($part$entry.lifecycle AND entry.dotted NOT IN ('iam.group','iam.user')$part$,
       $part$entry.lifecycle AND entry.dotted<>'iam.group'$part$),
      jsonb_build_array($part$WHEN dotted='iam.group' THEN model IS DISTINCT FROM 'iam_group'
    WHEN dotted='iam.user' THEN model IS DISTINCT FROM 'iam_user'$part$,
       $part$WHEN dotted='iam.group' THEN model IS DISTINCT FROM 'iam_group'$part$)
    )),
    ('_authority_access_label_generation_binding_read_hold_v1(jsonb,jsonb,jsonb,integer,integer,integer)','9dc26f010aaac554fd6a0d3aae5718c39504ebb85e07f2a5f6192e32b5db4bc3','b337730a6575cc7426186949fdab6f4bcc35a7f6616efa5902b58bf108943b03',
    jsonb_build_array(
      jsonb_build_array($part$'iam.serviceAccount','iam.group','iam.user') THEN CONTINUE;$part$,
       $part$'iam.serviceAccount','iam.group') THEN CONTINUE;$part$)
    )),
    ('_authority_access_label_object_generation_finish_v1(jsonb,jsonb,integer,integer)','10c43e01d6e1b930ee4c574e47007ca7154b797ee0c3ede41f520c210ecf7b1b','f6445458ff1427fae574a7dde7620462d55c1d95576129ab38fd2de92dbdb5a7',
    jsonb_build_array(
      jsonb_build_array($part$v_root_type IS DISTINCT FROM 'iam.group' AND v_root_type IS DISTINCT FROM 'iam.user' AND $part$,
       $part$v_root_type IS DISTINCT FROM 'iam.group' AND $part$)
    )),
    ('_authority_access_label_generation_discharge_v1(jsonb,jsonb,jsonb,jsonb,timestamptz,integer)','6f72d3bd3eb0489280a1e3cd3aa5d323ca5ac73a051b63b7b7e7b9822c16c3e4','34f60c48e3a6e6524482b989e0787c40403d59b48695fcfd95a74903c7c84260',
    jsonb_build_array(
      jsonb_build_array($part$(root_row->>'root_type') IS DISTINCT FROM 'iam.group' AND (root_row->>'root_type') IS DISTINCT FROM 'iam.user' AND $part$,
       $part$(root_row->>'root_type') IS DISTINCT FROM 'iam.group' AND $part$)
    )),
    ('_authority_access_label_generation_root_keys_v1(jsonb)','5b804b346bd94653d71ebc517e486413d3f4798cb05f7e7d0b48e84c3469e405','d401d36e3f917dedbdec49ba27e51821c17ea0e0a521cb1fc8cff4fef7ca9ab0',
    jsonb_build_array(
      jsonb_build_array($part$typ IS DISTINCT FROM 'iam.group' AND typ IS DISTINCT FROM 'iam.user' AND $part$,
       $part$typ IS DISTINCT FROM 'iam.group' AND $part$)
    )),
    ('authority_resource_reconcile_pending_v1(text,text,integer,integer)','83fdf25fd602ba09852eed3c74fd831128fa397cdcdb57a7b6c0d499ee1b750e','fb3f4cb89531f2b94ca68ed5ec6e604c484595b9ba1757c20d88f4236a49b024',
    jsonb_build_array(
      jsonb_build_array($part$('cluster','iam_role','iam_access_binding')$part$,
       $part$('cluster','iam_user','iam_role','iam_access_binding')$part$),
      jsonb_build_array($part$WHEN 'iam_group' THEN 'iam.group' WHEN 'iam_user' THEN 'iam.user' END;$part$,
       $part$WHEN 'iam_group' THEN 'iam.group' END;$part$)
    )),
    ('_authority_access_label_object_generation_capture_v1(text,text,integer,integer)','a42326162a99ba566ed1992209a43f81a9a464566f7aeffcc8716a293f1fdfac','5dfd98ff9eabebafdc94f2584fb9a80b8ea39dcd223b76497e495fbfcf5320b3',
    jsonb_build_array(
      jsonb_build_array($part$('cluster','iam_role','iam_access_binding')$part$,
       $part$('cluster','iam_user','iam_role','iam_access_binding')$part$),
      jsonb_build_array($part$WHEN 'iam_group' THEN 'iam.group' WHEN 'iam_user' THEN 'iam.user' END;$part$,
       $part$WHEN 'iam_group' THEN 'iam.group' END;$part$)
    ))
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'user generation worker contract predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'user generation worker contract replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'user generation worker contract body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'user generation worker contract installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_access_label_freshness_storage_v1() IS DISTINCT FROM true
        OR kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'user generation worker contract storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage_contract$;
-- +goose StatementEnd
