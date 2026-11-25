-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Пересчёт существующей группы удерживает K30 groups, K23 accounts и живую
-- строку каталога до сверки исходных меток и завершения поколения.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $storage_contract$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
    ('_authority_access_label_object_generation_capture_v1(text,text,integer,integer)','1cde79ac24f64479fa75e599239f24fdc46c98026567c3f09469b2da77f71dac','5dfd98ff9eabebafdc94f2584fb9a80b8ea39dcd223b76497e495fbfcf5320b3',
    jsonb_build_array(
        jsonb_build_array($part$WHEN 'iam_service_account' THEN 'iam.serviceAccount' END;$part$,
            $part$WHEN 'iam_service_account' THEN 'iam.serviceAccount'
  WHEN 'iam_group' THEN 'iam.group' END;$part$),
        jsonb_build_array($part$('cluster','iam_user','iam_group','iam_role','iam_access_binding')$part$,
            $part$('cluster','iam_user','iam_role','iam_access_binding')$part$)
    )),
    ('_authority_access_label_generation_root_keys_v1(jsonb)','5e041d5238e6326ba07a8fc988a53ec325b37ff3924c67b8845304891b05d530','d401d36e3f917dedbdec49ba27e51821c17ea0e0a521cb1fc8cff4fef7ca9ab0',
    jsonb_build_array(
        jsonb_build_array($part$kaname._authority_access_label_dirty_root_type_valid_v1(typ) IS DISTINCT FROM true$part$,
            $part$(typ IS DISTINCT FROM 'iam.group' AND kaname._authority_access_label_dirty_root_type_valid_v1(typ) IS DISTINCT FROM true)$part$)
    )),
    ('_authority_access_label_generation_binding_read_hold_v1(jsonb,jsonb,jsonb,integer,integer,integer)','740bbbb7903d3fe059561165d0ba4486b7d5fd15822c5a8881da20b3f7de157d','b337730a6575cc7426186949fdab6f4bcc35a7f6616efa5902b58bf108943b03',
    jsonb_build_array(
        jsonb_build_array($part$IF dotted IN ('iam.account','iam.project','iam.serviceAccount') THEN CONTINUE;$part$,
            $part$IF dotted IN ('iam.account','iam.project','iam.serviceAccount','iam.group') THEN CONTINUE;$part$)
    )),
    ('_authority_access_label_generation_graphs_v1(jsonb,jsonb,jsonb,jsonb)','a2a2707d6974b9526d199e5963fd96588db85f97d0bd0f6f9e7821c2f3d5c003','6e68a6ec865fee9afeaa80188179a24c88ce8df88a468a04dd487cf40f25ae1e',
    jsonb_build_array(
        jsonb_build_array($part$OR (lifecycle AND (model !~ '^[a-z][a-z0-9_]*$' OR split_part(dotted,'.',1)='iam'
    OR kaname._authority_access_label_dirty_root_type_valid_v1(dotted) IS DISTINCT FROM true))$part$,
            $part$OR (lifecycle AND CASE WHEN dotted='iam.group' THEN model IS DISTINCT FROM 'iam_group'
    ELSE model !~ '^[a-z][a-z0-9_]*$' OR split_part(dotted,'.',1)='iam'
     OR kaname._authority_access_label_dirty_root_type_valid_v1(dotted) IS DISTINCT FROM true END)$part$),
        jsonb_build_array($part$IF entry.lifecycle THEN$part$,
            $part$IF entry.lifecycle AND entry.dotted<>'iam.group' THEN$part$)
    )),
    ('_authority_access_label_generation_lifecycle_plan_v1(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,integer,integer,integer)','3f903b3dc8d1af5cf52841607f09df30d55ccc797b8e5d27d49e4d824666a100','0d5ac9c8cd03d40f17fd1d72a4581d2e3b3d7ba866d94808cd851f04027336e4',
    jsonb_build_array(
        jsonb_build_array($part$DECLARE root jsonb;dotted text;$part$,
            $part$DECLARE checked_group_sources boolean:=false;root jsonb;dotted text;$part$),
        jsonb_build_array($part$FOREACH kind IN ARRAY ARRAY[2,3,4,5,25,26,27,28] LOOP
   typ:=CASE WHEN kind=2 THEN dotted ELSE model END;$part$,
            $part$FOREACH kind IN ARRAY (CASE WHEN dotted='iam.group' THEN ARRAY[30] ELSE ARRAY[2,3,4,5,25,26,27,28] END) LOOP
   typ:=CASE WHEN kind IN (2,30) THEN dotted ELSE model END;$part$),
        jsonb_build_array($part$  required:='{}'::jsonb;predicates:='{}'::jsonb;$part$,
            $part$  IF dotted='iam.group' AND NOT checked_group_sources THEN
   -- Все три отношения уже удержаны catalog_wait и required_reread.
   used_rows:=used_rows+3;used_reads:=used_reads+1;checked_group_sources:=true;
   IF used_rows>p_rows OR used_reads>p_reads THEN
    RAISE EXCEPTION 'group generation source shape exceeds budget' USING ERRCODE='54000';END IF;
   IF (SELECT count(*) FROM pg_catalog.pg_class c
     WHERE c.oid IN ('kaname.groups'::regclass,'kaname.accounts'::regclass,'kaname.catalog_resource'::regclass)
      AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
      AND NOT c.relhasrules AND NOT c.relispartition AND NOT c.relhassubclass
      AND NOT EXISTS(SELECT FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid))<>3 THEN
    RAISE EXCEPTION 'group generation requires ordinary native sources' USING ERRCODE='42501';END IF;
  END IF;
  required:='{}'::jsonb;predicates:='{}'::jsonb;$part$),
        jsonb_build_array($part$    SELECT coalesce(jsonb_agg(jsonb_build_array(v->>'xmin',v->>'tid',v->'data')$part$,
            $part$    IF dotted='iam.group' AND (kind NOT IN (23,30)
     OR jsonb_array_length(p_current->entry.key)<>1
     OR p_current->entry.key->0->>'relation' IS DISTINCT FROM
        (CASE kind WHEN 23 THEN 'kaname.accounts'::regclass ELSE 'kaname.groups'::regclass END)::oid::text) THEN
     RAISE EXCEPTION 'group generation native held relation differs' USING ERRCODE='42501';END IF;
    SELECT coalesce(jsonb_agg(jsonb_build_array(v->>'xmin',v->>'tid',v->'data')$part$)
    )),
    ('_authority_access_label_generation_lifecycle_validate_v1(jsonb,jsonb)','20961329fbde39231a81df6cfdc98857b525475e9179c190998283f84a219859','5a6b46449f1f93880e2de0d4ce0efedeb89cf3613e3673fe62a8b0530ceb842f',
    jsonb_build_array(
        jsonb_build_array($part$kaname._authority_access_label_dirty_root_type_valid_v1(dotted) IS DISTINCT FROM true
 OR split_part(dotted,'.',1)='iam'$part$,
            $part$(dotted IS DISTINCT FROM 'iam.group' AND (kaname._authority_access_label_dirty_root_type_valid_v1(dotted) IS DISTINCT FROM true OR split_part(dotted,'.',1)='iam'))$part$),
        jsonb_build_array($part$ FOREACH kind IN ARRAY ARRAY[2,3,4,5,25,26,27,28] LOOP
  typ:=CASE WHEN kind=2 THEN dotted ELSE model END;$part$,
            $part$ IF dotted='iam.group' AND (
  model IS DISTINCT FROM 'iam_group' OR coalesce(identifier,'') COLLATE "C" !~ '^grp[a-zA-Z0-9_-]{1,61}$'
  OR raw->>'module' IS DISTINCT FROM 'iam' OR raw->>'resource' IS DISTINCT FROM 'group'
  OR raw->'live' IS DISTINCT FROM 'true'::jsonb OR p_lifecycle->'present' IS DISTINCT FROM 'true'::jsonb
  OR p_lifecycle->'projects' IS DISTINCT FROM '{}'::jsonb) THEN
  RAISE EXCEPTION 'group generation requires a live native account-scoped root' USING ERRCODE='42501';END IF;
 FOREACH kind IN ARRAY (CASE WHEN dotted='iam.group' THEN ARRAY[30] ELSE ARRAY[2,3,4,5,25,26,27,28] END) LOOP
  typ:=CASE WHEN kind IN (2,30) THEN dotted ELSE model END;$part$),
        jsonb_build_array($part$IF kind=23 AND jsonb_array_length(entry.value)<>1$part$,
            $part$IF kind IN (23,30) AND jsonb_array_length(entry.value)<>1$part$),
        jsonb_build_array($part$(kind IN (1,23) AND raw->>'id'$part$,
            $part$(kind IN (1,23,30) AND raw->>'id'$part$),
        jsonb_build_array($part$(kind NOT IN (1,23) AND (raw->>'object_type'$part$,
            $part$(kind NOT IN (1,23,30) AND (raw->>'object_type'$part$),
        jsonb_build_array($part$ source_key:=jsonb_build_array(2,dotted,identifier,'')::text;$part$,
            $part$ IF dotted='iam.group' THEN
  source_key:=jsonb_build_array(30,dotted,identifier,'')::text;
  raw:=p_lifecycle->'predicates'->source_key->0->2;
  IF coalesce(raw->>'account_id','') COLLATE "C" !~ '^acc[a-zA-Z0-9_-]{1,61}$'
   OR p_lifecycle->'accounts' IS DISTINCT FROM jsonb_build_object(coalesce(raw->>'account_id',''),true)
   OR raw->'access_labels' IS DISTINCT FROM p_root_state#>'{2,new_labels}'
   OR kaname.access_labels_valid_v1(raw->'access_labels') IS DISTINCT FROM true THEN
   RAISE EXCEPTION 'group generation held account or labels differ' USING ERRCODE='42501';END IF;
  RETURN jsonb_build_object('rows',rows_count,'reads',reads_count,'work',work);
 END IF;
 source_key:=jsonb_build_array(2,dotted,identifier,'')::text;$part$)
    )),
    ('_authority_access_label_generation_lifecycle_finish_v1(jsonb,jsonb,integer,integer)','f4b57581ee948805697006a7b8065408b93b3044a27eceb4dfa3807d79631903','c4ce49701c047a9b4bb14b1a0ed218ec794b41f493a8c9104275c6335b05296e',
    jsonb_build_array(
        jsonb_build_array($part$WHEN 23 THEN table_name:='accounts';$part$,
            $part$WHEN 23 THEN table_name:='accounts';
   WHEN 30 THEN table_name:='groups';$part$),
        jsonb_build_array($part$(k->>0)::integer IN (1,23)$part$,
            $part$(k->>0)::integer IN (1,23,30)$part$)
    )),
    ('_authority_access_label_generation_discharge_v1(jsonb,jsonb,jsonb,jsonb,timestamptz,integer)','3900dfe8f33716564059882e47ccd4ad734922493c53811595dd1b232f9ea484','34f60c48e3a6e6524482b989e0787c40403d59b48695fcfd95a74903c7c84260',
    jsonb_build_array(
        jsonb_build_array($part$kaname._authority_access_label_dirty_root_type_valid_v1(root_row->>'root_type') IS DISTINCT FROM true$part$,
            $part$((root_row->>'root_type') IS DISTINCT FROM 'iam.group' AND kaname._authority_access_label_dirty_root_type_valid_v1((root_row->>'root_type')) IS DISTINCT FROM true)$part$)
    )),
    ('_authority_access_label_object_generation_finish_v1(jsonb,jsonb,integer,integer)','024a76a4c696799f0fcb173696ae37b8e7a98a9f5bfd0de77348bb472b248e33','f6445458ff1427fae574a7dde7620462d55c1d95576129ab38fd2de92dbdb5a7',
    jsonb_build_array(
        jsonb_build_array($part$kaname._authority_access_label_dirty_root_type_valid_v1(v_root_type) IS DISTINCT FROM true$part$,
            $part$(v_root_type IS DISTINCT FROM 'iam.group' AND kaname._authority_access_label_dirty_root_type_valid_v1(v_root_type) IS DISTINCT FROM true)$part$)
    )),
    ('_authority_crud_storage_v3()','d96c861f7c4e639756685c0c1bc79ed3595e2cd67785339d57de23ba53c71983','713fda666ed49ca5d9858740a8093a6fa13476a056a6a7a87a868682950266fa',
    $changes$[
  [
    "1cde79ac24f64479fa75e599239f24fdc46c98026567c3f09469b2da77f71dac",
    "5dfd98ff9eabebafdc94f2584fb9a80b8ea39dcd223b76497e495fbfcf5320b3"
  ],
  [
    "5e041d5238e6326ba07a8fc988a53ec325b37ff3924c67b8845304891b05d530",
    "d401d36e3f917dedbdec49ba27e51821c17ea0e0a521cb1fc8cff4fef7ca9ab0"
  ],
  [
    "740bbbb7903d3fe059561165d0ba4486b7d5fd15822c5a8881da20b3f7de157d",
    "b337730a6575cc7426186949fdab6f4bcc35a7f6616efa5902b58bf108943b03"
  ],
  [
    "a2a2707d6974b9526d199e5963fd96588db85f97d0bd0f6f9e7821c2f3d5c003",
    "6e68a6ec865fee9afeaa80188179a24c88ce8df88a468a04dd487cf40f25ae1e"
  ],
  [
    "3f903b3dc8d1af5cf52841607f09df30d55ccc797b8e5d27d49e4d824666a100",
    "0d5ac9c8cd03d40f17fd1d72a4581d2e3b3d7ba866d94808cd851f04027336e4"
  ],
  [
    "20961329fbde39231a81df6cfdc98857b525475e9179c190998283f84a219859",
    "5a6b46449f1f93880e2de0d4ce0efedeb89cf3613e3673fe62a8b0530ceb842f"
  ],
  [
    "f4b57581ee948805697006a7b8065408b93b3044a27eceb4dfa3807d79631903",
    "c4ce49701c047a9b4bb14b1a0ed218ec794b41f493a8c9104275c6335b05296e"
  ],
  [
    "3900dfe8f33716564059882e47ccd4ad734922493c53811595dd1b232f9ea484",
    "34f60c48e3a6e6524482b989e0787c40403d59b48695fcfd95a74903c7c84260"
  ],
  [
    "024a76a4c696799f0fcb173696ae37b8e7a98a9f5bfd0de77348bb472b248e33",
    "f6445458ff1427fae574a7dde7620462d55c1d95576129ab38fd2de92dbdb5a7"
  ]
]$changes$::jsonb),
    ('_authority_full_contract_storage_v3()','03a1e896d6673fcfa062aa32b765dc3023f3775dc2d647d1ed80fbb067ac8463','a220bd43eeed2accacb9c7b02f4abcdc14cf53f9ec75bac242921eccd8016722',
    $changes$[
  [
    "d96c861f7c4e639756685c0c1bc79ed3595e2cd67785339d57de23ba53c71983",
    "713fda666ed49ca5d9858740a8093a6fa13476a056a6a7a87a868682950266fa"
  ]
]$changes$::jsonb),
    ('authority_metadata_service_account_access_label_ready_v1()','beccb669d7bffb4e9c6e9e7dac3a23bc936079d21fe7f3b2be4c215d44529126','cf60acefa0bb27eaf5a0ae35fd43d317b9de387e56df31b1023b4f01ce9a41c4',
    $changes$[
  [
    "1cde79ac24f64479fa75e599239f24fdc46c98026567c3f09469b2da77f71dac",
    "5dfd98ff9eabebafdc94f2584fb9a80b8ea39dcd223b76497e495fbfcf5320b3"
  ],
  [
    "5e041d5238e6326ba07a8fc988a53ec325b37ff3924c67b8845304891b05d530",
    "d401d36e3f917dedbdec49ba27e51821c17ea0e0a521cb1fc8cff4fef7ca9ab0"
  ],
  [
    "3900dfe8f33716564059882e47ccd4ad734922493c53811595dd1b232f9ea484",
    "34f60c48e3a6e6524482b989e0787c40403d59b48695fcfd95a74903c7c84260"
  ],
  [
    "024a76a4c696799f0fcb173696ae37b8e7a98a9f5bfd0de77348bb472b248e33",
    "f6445458ff1427fae574a7dde7620462d55c1d95576129ab38fd2de92dbdb5a7"
  ],
  [
    "d96c861f7c4e639756685c0c1bc79ed3595e2cd67785339d57de23ba53c71983",
    "713fda666ed49ca5d9858740a8093a6fa13476a056a6a7a87a868682950266fa"
  ],
  [
    "03a1e896d6673fcfa062aa32b765dc3023f3775dc2d647d1ed80fbb067ac8463",
    "a220bd43eeed2accacb9c7b02f4abcdc14cf53f9ec75bac242921eccd8016722"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'group generation worker contract predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'group generation worker contract replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'group generation worker contract body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'group generation worker contract installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_access_label_freshness_storage_v1() IS DISTINCT FROM true
        OR kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'group generation worker contract storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage_contract$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $storage_contract$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
    ('authority_metadata_service_account_access_label_ready_v1()','cf60acefa0bb27eaf5a0ae35fd43d317b9de387e56df31b1023b4f01ce9a41c4','beccb669d7bffb4e9c6e9e7dac3a23bc936079d21fe7f3b2be4c215d44529126',
    $changes$[
  [
    "a220bd43eeed2accacb9c7b02f4abcdc14cf53f9ec75bac242921eccd8016722",
    "03a1e896d6673fcfa062aa32b765dc3023f3775dc2d647d1ed80fbb067ac8463"
  ],
  [
    "713fda666ed49ca5d9858740a8093a6fa13476a056a6a7a87a868682950266fa",
    "d96c861f7c4e639756685c0c1bc79ed3595e2cd67785339d57de23ba53c71983"
  ],
  [
    "f6445458ff1427fae574a7dde7620462d55c1d95576129ab38fd2de92dbdb5a7",
    "024a76a4c696799f0fcb173696ae37b8e7a98a9f5bfd0de77348bb472b248e33"
  ],
  [
    "34f60c48e3a6e6524482b989e0787c40403d59b48695fcfd95a74903c7c84260",
    "3900dfe8f33716564059882e47ccd4ad734922493c53811595dd1b232f9ea484"
  ],
  [
    "d401d36e3f917dedbdec49ba27e51821c17ea0e0a521cb1fc8cff4fef7ca9ab0",
    "5e041d5238e6326ba07a8fc988a53ec325b37ff3924c67b8845304891b05d530"
  ],
  [
    "5dfd98ff9eabebafdc94f2584fb9a80b8ea39dcd223b76497e495fbfcf5320b3",
    "1cde79ac24f64479fa75e599239f24fdc46c98026567c3f09469b2da77f71dac"
  ]
]$changes$::jsonb),
    ('_authority_full_contract_storage_v3()','a220bd43eeed2accacb9c7b02f4abcdc14cf53f9ec75bac242921eccd8016722','03a1e896d6673fcfa062aa32b765dc3023f3775dc2d647d1ed80fbb067ac8463',
    $changes$[
  [
    "713fda666ed49ca5d9858740a8093a6fa13476a056a6a7a87a868682950266fa",
    "d96c861f7c4e639756685c0c1bc79ed3595e2cd67785339d57de23ba53c71983"
  ]
]$changes$::jsonb),
    ('_authority_crud_storage_v3()','713fda666ed49ca5d9858740a8093a6fa13476a056a6a7a87a868682950266fa','d96c861f7c4e639756685c0c1bc79ed3595e2cd67785339d57de23ba53c71983',
    $changes$[
  [
    "f6445458ff1427fae574a7dde7620462d55c1d95576129ab38fd2de92dbdb5a7",
    "024a76a4c696799f0fcb173696ae37b8e7a98a9f5bfd0de77348bb472b248e33"
  ],
  [
    "34f60c48e3a6e6524482b989e0787c40403d59b48695fcfd95a74903c7c84260",
    "3900dfe8f33716564059882e47ccd4ad734922493c53811595dd1b232f9ea484"
  ],
  [
    "c4ce49701c047a9b4bb14b1a0ed218ec794b41f493a8c9104275c6335b05296e",
    "f4b57581ee948805697006a7b8065408b93b3044a27eceb4dfa3807d79631903"
  ],
  [
    "5a6b46449f1f93880e2de0d4ce0efedeb89cf3613e3673fe62a8b0530ceb842f",
    "20961329fbde39231a81df6cfdc98857b525475e9179c190998283f84a219859"
  ],
  [
    "0d5ac9c8cd03d40f17fd1d72a4581d2e3b3d7ba866d94808cd851f04027336e4",
    "3f903b3dc8d1af5cf52841607f09df30d55ccc797b8e5d27d49e4d824666a100"
  ],
  [
    "6e68a6ec865fee9afeaa80188179a24c88ce8df88a468a04dd487cf40f25ae1e",
    "a2a2707d6974b9526d199e5963fd96588db85f97d0bd0f6f9e7821c2f3d5c003"
  ],
  [
    "b337730a6575cc7426186949fdab6f4bcc35a7f6616efa5902b58bf108943b03",
    "740bbbb7903d3fe059561165d0ba4486b7d5fd15822c5a8881da20b3f7de157d"
  ],
  [
    "d401d36e3f917dedbdec49ba27e51821c17ea0e0a521cb1fc8cff4fef7ca9ab0",
    "5e041d5238e6326ba07a8fc988a53ec325b37ff3924c67b8845304891b05d530"
  ],
  [
    "5dfd98ff9eabebafdc94f2584fb9a80b8ea39dcd223b76497e495fbfcf5320b3",
    "1cde79ac24f64479fa75e599239f24fdc46c98026567c3f09469b2da77f71dac"
  ]
]$changes$::jsonb),
    ('_authority_access_label_object_generation_finish_v1(jsonb,jsonb,integer,integer)','f6445458ff1427fae574a7dde7620462d55c1d95576129ab38fd2de92dbdb5a7','024a76a4c696799f0fcb173696ae37b8e7a98a9f5bfd0de77348bb472b248e33',
    jsonb_build_array(
        jsonb_build_array($part$(v_root_type IS DISTINCT FROM 'iam.group' AND kaname._authority_access_label_dirty_root_type_valid_v1(v_root_type) IS DISTINCT FROM true)$part$,
            $part$kaname._authority_access_label_dirty_root_type_valid_v1(v_root_type) IS DISTINCT FROM true$part$)
    )),
    ('_authority_access_label_generation_discharge_v1(jsonb,jsonb,jsonb,jsonb,timestamptz,integer)','34f60c48e3a6e6524482b989e0787c40403d59b48695fcfd95a74903c7c84260','3900dfe8f33716564059882e47ccd4ad734922493c53811595dd1b232f9ea484',
    jsonb_build_array(
        jsonb_build_array($part$((root_row->>'root_type') IS DISTINCT FROM 'iam.group' AND kaname._authority_access_label_dirty_root_type_valid_v1((root_row->>'root_type')) IS DISTINCT FROM true)$part$,
            $part$kaname._authority_access_label_dirty_root_type_valid_v1(root_row->>'root_type') IS DISTINCT FROM true$part$)
    )),
    ('_authority_access_label_generation_lifecycle_finish_v1(jsonb,jsonb,integer,integer)','c4ce49701c047a9b4bb14b1a0ed218ec794b41f493a8c9104275c6335b05296e','f4b57581ee948805697006a7b8065408b93b3044a27eceb4dfa3807d79631903',
    jsonb_build_array(
        jsonb_build_array($part$(k->>0)::integer IN (1,23,30)$part$,
            $part$(k->>0)::integer IN (1,23)$part$),
        jsonb_build_array($part$WHEN 23 THEN table_name:='accounts';
   WHEN 30 THEN table_name:='groups';$part$,
            $part$WHEN 23 THEN table_name:='accounts';$part$)
    )),
    ('_authority_access_label_generation_lifecycle_validate_v1(jsonb,jsonb)','5a6b46449f1f93880e2de0d4ce0efedeb89cf3613e3673fe62a8b0530ceb842f','20961329fbde39231a81df6cfdc98857b525475e9179c190998283f84a219859',
    jsonb_build_array(
        jsonb_build_array($part$ IF dotted='iam.group' THEN
  source_key:=jsonb_build_array(30,dotted,identifier,'')::text;
  raw:=p_lifecycle->'predicates'->source_key->0->2;
  IF coalesce(raw->>'account_id','') COLLATE "C" !~ '^acc[a-zA-Z0-9_-]{1,61}$'
   OR p_lifecycle->'accounts' IS DISTINCT FROM jsonb_build_object(coalesce(raw->>'account_id',''),true)
   OR raw->'access_labels' IS DISTINCT FROM p_root_state#>'{2,new_labels}'
   OR kaname.access_labels_valid_v1(raw->'access_labels') IS DISTINCT FROM true THEN
   RAISE EXCEPTION 'group generation held account or labels differ' USING ERRCODE='42501';END IF;
  RETURN jsonb_build_object('rows',rows_count,'reads',reads_count,'work',work);
 END IF;
 source_key:=jsonb_build_array(2,dotted,identifier,'')::text;$part$,
            $part$ source_key:=jsonb_build_array(2,dotted,identifier,'')::text;$part$),
        jsonb_build_array($part$(kind NOT IN (1,23,30) AND (raw->>'object_type'$part$,
            $part$(kind NOT IN (1,23) AND (raw->>'object_type'$part$),
        jsonb_build_array($part$(kind IN (1,23,30) AND raw->>'id'$part$,
            $part$(kind IN (1,23) AND raw->>'id'$part$),
        jsonb_build_array($part$IF kind IN (23,30) AND jsonb_array_length(entry.value)<>1$part$,
            $part$IF kind=23 AND jsonb_array_length(entry.value)<>1$part$),
        jsonb_build_array($part$ IF dotted='iam.group' AND (
  model IS DISTINCT FROM 'iam_group' OR coalesce(identifier,'') COLLATE "C" !~ '^grp[a-zA-Z0-9_-]{1,61}$'
  OR raw->>'module' IS DISTINCT FROM 'iam' OR raw->>'resource' IS DISTINCT FROM 'group'
  OR raw->'live' IS DISTINCT FROM 'true'::jsonb OR p_lifecycle->'present' IS DISTINCT FROM 'true'::jsonb
  OR p_lifecycle->'projects' IS DISTINCT FROM '{}'::jsonb) THEN
  RAISE EXCEPTION 'group generation requires a live native account-scoped root' USING ERRCODE='42501';END IF;
 FOREACH kind IN ARRAY (CASE WHEN dotted='iam.group' THEN ARRAY[30] ELSE ARRAY[2,3,4,5,25,26,27,28] END) LOOP
  typ:=CASE WHEN kind IN (2,30) THEN dotted ELSE model END;$part$,
            $part$ FOREACH kind IN ARRAY ARRAY[2,3,4,5,25,26,27,28] LOOP
  typ:=CASE WHEN kind=2 THEN dotted ELSE model END;$part$),
        jsonb_build_array($part$(dotted IS DISTINCT FROM 'iam.group' AND (kaname._authority_access_label_dirty_root_type_valid_v1(dotted) IS DISTINCT FROM true OR split_part(dotted,'.',1)='iam'))$part$,
            $part$kaname._authority_access_label_dirty_root_type_valid_v1(dotted) IS DISTINCT FROM true
 OR split_part(dotted,'.',1)='iam'$part$)
    )),
    ('_authority_access_label_generation_lifecycle_plan_v1(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,integer,integer,integer)','0d5ac9c8cd03d40f17fd1d72a4581d2e3b3d7ba866d94808cd851f04027336e4','3f903b3dc8d1af5cf52841607f09df30d55ccc797b8e5d27d49e4d824666a100',
    jsonb_build_array(
        jsonb_build_array($part$    IF dotted='iam.group' AND (kind NOT IN (23,30)
     OR jsonb_array_length(p_current->entry.key)<>1
     OR p_current->entry.key->0->>'relation' IS DISTINCT FROM
        (CASE kind WHEN 23 THEN 'kaname.accounts'::regclass ELSE 'kaname.groups'::regclass END)::oid::text) THEN
     RAISE EXCEPTION 'group generation native held relation differs' USING ERRCODE='42501';END IF;
    SELECT coalesce(jsonb_agg(jsonb_build_array(v->>'xmin',v->>'tid',v->'data')$part$,
            $part$    SELECT coalesce(jsonb_agg(jsonb_build_array(v->>'xmin',v->>'tid',v->'data')$part$),
        jsonb_build_array($part$  IF dotted='iam.group' AND NOT checked_group_sources THEN
   -- Все три отношения уже удержаны catalog_wait и required_reread.
   used_rows:=used_rows+3;used_reads:=used_reads+1;checked_group_sources:=true;
   IF used_rows>p_rows OR used_reads>p_reads THEN
    RAISE EXCEPTION 'group generation source shape exceeds budget' USING ERRCODE='54000';END IF;
   IF (SELECT count(*) FROM pg_catalog.pg_class c
     WHERE c.oid IN ('kaname.groups'::regclass,'kaname.accounts'::regclass,'kaname.catalog_resource'::regclass)
      AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
      AND NOT c.relhasrules AND NOT c.relispartition AND NOT c.relhassubclass
      AND NOT EXISTS(SELECT FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid))<>3 THEN
    RAISE EXCEPTION 'group generation requires ordinary native sources' USING ERRCODE='42501';END IF;
  END IF;
  required:='{}'::jsonb;predicates:='{}'::jsonb;$part$,
            $part$  required:='{}'::jsonb;predicates:='{}'::jsonb;$part$),
        jsonb_build_array($part$FOREACH kind IN ARRAY (CASE WHEN dotted='iam.group' THEN ARRAY[30] ELSE ARRAY[2,3,4,5,25,26,27,28] END) LOOP
   typ:=CASE WHEN kind IN (2,30) THEN dotted ELSE model END;$part$,
            $part$FOREACH kind IN ARRAY ARRAY[2,3,4,5,25,26,27,28] LOOP
   typ:=CASE WHEN kind=2 THEN dotted ELSE model END;$part$),
        jsonb_build_array($part$DECLARE checked_group_sources boolean:=false;root jsonb;dotted text;$part$,
            $part$DECLARE root jsonb;dotted text;$part$)
    )),
    ('_authority_access_label_generation_graphs_v1(jsonb,jsonb,jsonb,jsonb)','6e68a6ec865fee9afeaa80188179a24c88ce8df88a468a04dd487cf40f25ae1e','a2a2707d6974b9526d199e5963fd96588db85f97d0bd0f6f9e7821c2f3d5c003',
    jsonb_build_array(
        jsonb_build_array($part$IF entry.lifecycle AND entry.dotted<>'iam.group' THEN$part$,
            $part$IF entry.lifecycle THEN$part$),
        jsonb_build_array($part$OR (lifecycle AND CASE WHEN dotted='iam.group' THEN model IS DISTINCT FROM 'iam_group'
    ELSE model !~ '^[a-z][a-z0-9_]*$' OR split_part(dotted,'.',1)='iam'
     OR kaname._authority_access_label_dirty_root_type_valid_v1(dotted) IS DISTINCT FROM true END)$part$,
            $part$OR (lifecycle AND (model !~ '^[a-z][a-z0-9_]*$' OR split_part(dotted,'.',1)='iam'
    OR kaname._authority_access_label_dirty_root_type_valid_v1(dotted) IS DISTINCT FROM true))$part$)
    )),
    ('_authority_access_label_generation_binding_read_hold_v1(jsonb,jsonb,jsonb,integer,integer,integer)','b337730a6575cc7426186949fdab6f4bcc35a7f6616efa5902b58bf108943b03','740bbbb7903d3fe059561165d0ba4486b7d5fd15822c5a8881da20b3f7de157d',
    jsonb_build_array(
        jsonb_build_array($part$IF dotted IN ('iam.account','iam.project','iam.serviceAccount','iam.group') THEN CONTINUE;$part$,
            $part$IF dotted IN ('iam.account','iam.project','iam.serviceAccount') THEN CONTINUE;$part$)
    )),
    ('_authority_access_label_generation_root_keys_v1(jsonb)','d401d36e3f917dedbdec49ba27e51821c17ea0e0a521cb1fc8cff4fef7ca9ab0','5e041d5238e6326ba07a8fc988a53ec325b37ff3924c67b8845304891b05d530',
    jsonb_build_array(
        jsonb_build_array($part$(typ IS DISTINCT FROM 'iam.group' AND kaname._authority_access_label_dirty_root_type_valid_v1(typ) IS DISTINCT FROM true)$part$,
            $part$kaname._authority_access_label_dirty_root_type_valid_v1(typ) IS DISTINCT FROM true$part$)
    )),
    ('_authority_access_label_object_generation_capture_v1(text,text,integer,integer)','5dfd98ff9eabebafdc94f2584fb9a80b8ea39dcd223b76497e495fbfcf5320b3','1cde79ac24f64479fa75e599239f24fdc46c98026567c3f09469b2da77f71dac',
    jsonb_build_array(
        jsonb_build_array($part$('cluster','iam_user','iam_role','iam_access_binding')$part$,
            $part$('cluster','iam_user','iam_group','iam_role','iam_access_binding')$part$),
        jsonb_build_array($part$WHEN 'iam_service_account' THEN 'iam.serviceAccount'
  WHEN 'iam_group' THEN 'iam.group' END;$part$,
            $part$WHEN 'iam_service_account' THEN 'iam.serviceAccount' END;$part$)
    ))
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'group generation worker contract predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'group generation worker contract replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'group generation worker contract body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'group generation worker contract installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_access_label_freshness_storage_v1() IS DISTINCT FROM true
        OR kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'group generation worker contract storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage_contract$;
-- +goose StatementEnd
