-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

LOCK TABLE kaname.authority_access_label_dirty_root,kaname.authority_access_label_dirty_fact IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $predecessor$
BEGIN
 IF kaname._authority_access_label_freshness_storage_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'group generation storage predecessor shape differs' USING ERRCODE='55000';END IF;
END;
$predecessor$;
-- +goose StatementEnd

-- Только исходная строка groups может нести поколение iam.group. Общий
-- валидатор старых путей остаётся закрытым для неё до подключения worker.
ALTER TABLE kaname.authority_access_label_dirty_root DROP CONSTRAINT authority_access_label_dirty_root_type;
ALTER TABLE kaname.authority_access_label_dirty_root ADD CONSTRAINT authority_access_label_dirty_root_type
 CHECK (root_type='iam.group' OR kaname._authority_access_label_dirty_root_type_valid_v1(root_type));

-- +goose StatementBegin
DO $storage_contract$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
    ('_authority_metadata_access_label_carry_v1(text,text,jsonb,integer,integer)','45ab208874926a028090e251b2440a6304de296fdc5424dba056a6fc1f1892cf','1ad72a671f2522c1b9e3d59c24c06d9e3f281ba57ff6973f1250e2f5a7f3b5e8',
    jsonb_build_array(
        jsonb_build_array($part$ external_root boolean;prepared jsonb;$part$,
            $part$ prepared jsonb;$part$),
        jsonb_build_array($part$IF kaname._authority_access_label_dirty_root_type_valid_v1(p_root_type) IS DISTINCT FROM true OR coalesce(p_root_id,'')=''$part$,
            $part$IF (p_root_type IS DISTINCT FROM 'iam.group' AND kaname._authority_access_label_dirty_root_type_valid_v1(p_root_type) IS DISTINCT FROM true)
  OR coalesce(p_root_id,'')=''$part$),
        jsonb_build_array($part$ external_root:=p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount');
 IF external_root THEN$part$,
            $part$ IF p_root_type='iam.group' THEN
  -- Резервируем чтения stash, физического OLD и строки поколения до блокировок.
  base_rows:=3;base_reads:=3;
  IF p_rows<base_rows OR p_reads<base_reads THEN
   RAISE EXCEPTION 'group access label freshness carry budget exhausted' USING ERRCODE='54000';END IF;
  prepared:=kaname._authority_metadata_access_label_stashed_v1();
  retained:=prepared->'retention';
  physical:=retained->'root_physical';
  IF p_root_id COLLATE "C" !~ '^grp[a-zA-Z0-9_-]{1,61}$'
   OR prepared#>'{root,root_coordinate}' IS DISTINCT FROM jsonb_build_array('iam.group',p_root_id)
   OR retained->>'root_type' IS DISTINCT FROM 'iam.group' OR retained->>'root_id' IS DISTINCT FROM p_root_id
   OR retained->>'root_model' IS DISTINCT FROM 'iam_group' OR retained->'root_source_kind' IS DISTINCT FROM '30'::jsonb
   OR retained#>>'{old_row,id}' IS DISTINCT FROM p_root_id
   OR coalesce(retained#>>'{old_row,account_id}','') COLLATE "C" !~ '^acc[a-zA-Z0-9_-]{1,61}$'
   OR retained#>>'{old_row,account_id}' IS DISTINCT FROM prepared#>>'{root,root_account}'
   OR retained#>'{old_row,access_labels}' IS DISTINCT FROM p_old_labels
   OR retained->'old_row' IS DISTINCT FROM prepared#>'{root,root_state,2}'
   OR retained#>ARRAY['source_index',jsonb_build_array(30,'iam.group',p_root_id,'')::text,'states','0']
      IS DISTINCT FROM prepared#>'{root,root_state}'
   OR physical IS DISTINCT FROM jsonb_build_object('table','groups','id',p_root_id,
      'xmin',prepared#>>'{root,root_state,0}','ctid',prepared#>>'{root,root_state,1}') THEN
   RAISE EXCEPTION 'group access label freshness root is not held' USING ERRCODE='42501';END IF;
  SELECT to_jsonb(g),g.xmin::text,g.ctid::text INTO actual_row,actual_xmin,actual_ctid
  FROM ONLY kaname.groups g WHERE g.id=p_root_id;
  IF NOT FOUND OR actual_row IS DISTINCT FROM retained->'old_row'
   OR actual_xmin IS DISTINCT FROM physical->>'xmin' OR actual_ctid IS DISTINCT FROM physical->>'ctid' THEN
   RAISE EXCEPTION 'group access label freshness root changed during carry' USING ERRCODE='40001';END IF;
 ELSIF p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') THEN$part$)
    )),
    ('authority_resource_reconcile_pending_v1(text,text,integer,integer)','6d15745d3afe3ea6e46cc82bbbbf8ab2c0d650f3a36e332bd49dee8d5fd79a8f','fb3f4cb89531f2b94ca68ed5ec6e604c484595b9ba1757c20d88f4236a49b024',
    jsonb_build_array(
        jsonb_build_array($part$WHEN 'iam_service_account' THEN 'iam.serviceAccount' END;$part$,
            $part$WHEN 'iam_service_account' THEN 'iam.serviceAccount'
  WHEN 'iam_group' THEN 'iam.group' END;$part$),
        jsonb_build_array($part$('cluster','iam_user','iam_group','iam_role','iam_access_binding')$part$,
            $part$('cluster','iam_user','iam_role','iam_access_binding')$part$)
    )),
    ('_authority_access_label_freshness_storage_v1()','d5892bc3912e46c57530c959d730e4a669707c34271798caa5a08cc954aed087','3d124bbd2209903ee01236e8d402d2773e964fb9de79ca39171dda88e0b4ef87',
    $changes$[
  [
    "kaname._authority_access_label_dirty_root_type_valid_v1root_type",
    "root_type=''iam.group''::textORkaname._authority_access_label_dirty_root_type_valid_v1root_type"
  ]
]$changes$::jsonb),
    ('_authority_full_contract_storage_v3()','e6e87e217e3323d3952cf2df43674d96eee9798fb6bd797766c583aa4ea703fe','03a1e896d6673fcfa062aa32b765dc3023f3775dc2d647d1ed80fbb067ac8463',
    $changes$[
  [
    "d5892bc3912e46c57530c959d730e4a669707c34271798caa5a08cc954aed087",
    "3d124bbd2209903ee01236e8d402d2773e964fb9de79ca39171dda88e0b4ef87"
  ]
]$changes$::jsonb),
    ('authority_metadata_access_label_ready_v2(text)','198d63dd8dc6d1c112a124ea06399a521ad37cf0402a8ed78a4ca105b80f0252','bdb897e826d43c2a1c9c2f9ead3f7192c80dc1ef8bc2dd64931ca330b852c39e',
    $changes$[
  [
    "45ab208874926a028090e251b2440a6304de296fdc5424dba056a6fc1f1892cf",
    "1ad72a671f2522c1b9e3d59c24c06d9e3f281ba57ff6973f1250e2f5a7f3b5e8"
  ]
]$changes$::jsonb),
    ('authority_metadata_service_account_access_label_ready_v1()','0aed46c8be81a3e34bcb687190ea94caf7da29857b16206f76e3f7b550596f7a','beccb669d7bffb4e9c6e9e7dac3a23bc936079d21fe7f3b2be4c215d44529126',
    $changes$[
  [
    "45ab208874926a028090e251b2440a6304de296fdc5424dba056a6fc1f1892cf",
    "1ad72a671f2522c1b9e3d59c24c06d9e3f281ba57ff6973f1250e2f5a7f3b5e8"
  ],
  [
    "6d15745d3afe3ea6e46cc82bbbbf8ab2c0d650f3a36e332bd49dee8d5fd79a8f",
    "fb3f4cb89531f2b94ca68ed5ec6e604c484595b9ba1757c20d88f4236a49b024"
  ],
  [
    "d5892bc3912e46c57530c959d730e4a669707c34271798caa5a08cc954aed087",
    "3d124bbd2209903ee01236e8d402d2773e964fb9de79ca39171dda88e0b4ef87"
  ],
  [
    "e6e87e217e3323d3952cf2df43674d96eee9798fb6bd797766c583aa4ea703fe",
    "03a1e896d6673fcfa062aa32b765dc3023f3775dc2d647d1ed80fbb067ac8463"
  ],
  [
    "198d63dd8dc6d1c112a124ea06399a521ad37cf0402a8ed78a4ca105b80f0252",
    "bdb897e826d43c2a1c9c2f9ead3f7192c80dc1ef8bc2dd64931ca330b852c39e"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'group generation storage contract predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'group generation storage contract replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'group generation storage contract body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'group generation storage contract installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_access_label_freshness_storage_v1() IS DISTINCT FROM true
        OR kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'group generation storage contract storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage_contract$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

LOCK TABLE kaname.authority_access_label_dirty_root,kaname.authority_access_label_dirty_fact IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $predecessor$
BEGIN
 IF kaname._authority_access_label_freshness_storage_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'group generation storage predecessor shape differs' USING ERRCODE='55000';END IF;
END;
$predecessor$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $pending$
BEGIN
 IF EXISTS(SELECT FROM ONLY kaname.authority_access_label_dirty_root WHERE root_type='iam.group') THEN
  RAISE EXCEPTION 'Сначала завершите пересчёт прав групп' USING ERRCODE='55000';END IF;
END;
$pending$;
-- +goose StatementEnd
ALTER TABLE kaname.authority_access_label_dirty_root DROP CONSTRAINT authority_access_label_dirty_root_type;
ALTER TABLE kaname.authority_access_label_dirty_root ADD CONSTRAINT authority_access_label_dirty_root_type
 CHECK (kaname._authority_access_label_dirty_root_type_valid_v1(root_type));

-- +goose StatementBegin
DO $storage_contract$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
    ('authority_metadata_service_account_access_label_ready_v1()','beccb669d7bffb4e9c6e9e7dac3a23bc936079d21fe7f3b2be4c215d44529126','0aed46c8be81a3e34bcb687190ea94caf7da29857b16206f76e3f7b550596f7a',
    $changes$[
  [
    "bdb897e826d43c2a1c9c2f9ead3f7192c80dc1ef8bc2dd64931ca330b852c39e",
    "198d63dd8dc6d1c112a124ea06399a521ad37cf0402a8ed78a4ca105b80f0252"
  ],
  [
    "03a1e896d6673fcfa062aa32b765dc3023f3775dc2d647d1ed80fbb067ac8463",
    "e6e87e217e3323d3952cf2df43674d96eee9798fb6bd797766c583aa4ea703fe"
  ],
  [
    "3d124bbd2209903ee01236e8d402d2773e964fb9de79ca39171dda88e0b4ef87",
    "d5892bc3912e46c57530c959d730e4a669707c34271798caa5a08cc954aed087"
  ],
  [
    "fb3f4cb89531f2b94ca68ed5ec6e604c484595b9ba1757c20d88f4236a49b024",
    "6d15745d3afe3ea6e46cc82bbbbf8ab2c0d650f3a36e332bd49dee8d5fd79a8f"
  ],
  [
    "1ad72a671f2522c1b9e3d59c24c06d9e3f281ba57ff6973f1250e2f5a7f3b5e8",
    "45ab208874926a028090e251b2440a6304de296fdc5424dba056a6fc1f1892cf"
  ]
]$changes$::jsonb),
    ('authority_metadata_access_label_ready_v2(text)','bdb897e826d43c2a1c9c2f9ead3f7192c80dc1ef8bc2dd64931ca330b852c39e','198d63dd8dc6d1c112a124ea06399a521ad37cf0402a8ed78a4ca105b80f0252',
    $changes$[
  [
    "1ad72a671f2522c1b9e3d59c24c06d9e3f281ba57ff6973f1250e2f5a7f3b5e8",
    "45ab208874926a028090e251b2440a6304de296fdc5424dba056a6fc1f1892cf"
  ]
]$changes$::jsonb),
    ('_authority_full_contract_storage_v3()','03a1e896d6673fcfa062aa32b765dc3023f3775dc2d647d1ed80fbb067ac8463','e6e87e217e3323d3952cf2df43674d96eee9798fb6bd797766c583aa4ea703fe',
    $changes$[
  [
    "3d124bbd2209903ee01236e8d402d2773e964fb9de79ca39171dda88e0b4ef87",
    "d5892bc3912e46c57530c959d730e4a669707c34271798caa5a08cc954aed087"
  ]
]$changes$::jsonb),
    ('_authority_access_label_freshness_storage_v1()','3d124bbd2209903ee01236e8d402d2773e964fb9de79ca39171dda88e0b4ef87','d5892bc3912e46c57530c959d730e4a669707c34271798caa5a08cc954aed087',
    $changes$[
  [
    "root_type=''iam.group''::textORkaname._authority_access_label_dirty_root_type_valid_v1root_type",
    "kaname._authority_access_label_dirty_root_type_valid_v1root_type"
  ]
]$changes$::jsonb),
    ('authority_resource_reconcile_pending_v1(text,text,integer,integer)','fb3f4cb89531f2b94ca68ed5ec6e604c484595b9ba1757c20d88f4236a49b024','6d15745d3afe3ea6e46cc82bbbbf8ab2c0d650f3a36e332bd49dee8d5fd79a8f',
    jsonb_build_array(
        jsonb_build_array($part$('cluster','iam_user','iam_role','iam_access_binding')$part$,
            $part$('cluster','iam_user','iam_group','iam_role','iam_access_binding')$part$),
        jsonb_build_array($part$WHEN 'iam_service_account' THEN 'iam.serviceAccount'
  WHEN 'iam_group' THEN 'iam.group' END;$part$,
            $part$WHEN 'iam_service_account' THEN 'iam.serviceAccount' END;$part$)
    )),
    ('_authority_metadata_access_label_carry_v1(text,text,jsonb,integer,integer)','1ad72a671f2522c1b9e3d59c24c06d9e3f281ba57ff6973f1250e2f5a7f3b5e8','45ab208874926a028090e251b2440a6304de296fdc5424dba056a6fc1f1892cf',
    jsonb_build_array(
        jsonb_build_array($part$ IF p_root_type='iam.group' THEN
  -- Резервируем чтения stash, физического OLD и строки поколения до блокировок.
  base_rows:=3;base_reads:=3;
  IF p_rows<base_rows OR p_reads<base_reads THEN
   RAISE EXCEPTION 'group access label freshness carry budget exhausted' USING ERRCODE='54000';END IF;
  prepared:=kaname._authority_metadata_access_label_stashed_v1();
  retained:=prepared->'retention';
  physical:=retained->'root_physical';
  IF p_root_id COLLATE "C" !~ '^grp[a-zA-Z0-9_-]{1,61}$'
   OR prepared#>'{root,root_coordinate}' IS DISTINCT FROM jsonb_build_array('iam.group',p_root_id)
   OR retained->>'root_type' IS DISTINCT FROM 'iam.group' OR retained->>'root_id' IS DISTINCT FROM p_root_id
   OR retained->>'root_model' IS DISTINCT FROM 'iam_group' OR retained->'root_source_kind' IS DISTINCT FROM '30'::jsonb
   OR retained#>>'{old_row,id}' IS DISTINCT FROM p_root_id
   OR coalesce(retained#>>'{old_row,account_id}','') COLLATE "C" !~ '^acc[a-zA-Z0-9_-]{1,61}$'
   OR retained#>>'{old_row,account_id}' IS DISTINCT FROM prepared#>>'{root,root_account}'
   OR retained#>'{old_row,access_labels}' IS DISTINCT FROM p_old_labels
   OR retained->'old_row' IS DISTINCT FROM prepared#>'{root,root_state,2}'
   OR retained#>ARRAY['source_index',jsonb_build_array(30,'iam.group',p_root_id,'')::text,'states','0']
      IS DISTINCT FROM prepared#>'{root,root_state}'
   OR physical IS DISTINCT FROM jsonb_build_object('table','groups','id',p_root_id,
      'xmin',prepared#>>'{root,root_state,0}','ctid',prepared#>>'{root,root_state,1}') THEN
   RAISE EXCEPTION 'group access label freshness root is not held' USING ERRCODE='42501';END IF;
  SELECT to_jsonb(g),g.xmin::text,g.ctid::text INTO actual_row,actual_xmin,actual_ctid
  FROM ONLY kaname.groups g WHERE g.id=p_root_id;
  IF NOT FOUND OR actual_row IS DISTINCT FROM retained->'old_row'
   OR actual_xmin IS DISTINCT FROM physical->>'xmin' OR actual_ctid IS DISTINCT FROM physical->>'ctid' THEN
   RAISE EXCEPTION 'group access label freshness root changed during carry' USING ERRCODE='40001';END IF;
 ELSIF p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') THEN$part$,
            $part$ external_root:=p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount');
 IF external_root THEN$part$),
        jsonb_build_array($part$IF (p_root_type IS DISTINCT FROM 'iam.group' AND kaname._authority_access_label_dirty_root_type_valid_v1(p_root_type) IS DISTINCT FROM true)
  OR coalesce(p_root_id,'')=''$part$,
            $part$IF kaname._authority_access_label_dirty_root_type_valid_v1(p_root_type) IS DISTINCT FROM true OR coalesce(p_root_id,'')=''$part$),
        jsonb_build_array($part$ prepared jsonb;$part$,
            $part$ external_root boolean;prepared jsonb;$part$)
    ))
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'group generation storage contract predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'group generation storage contract replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'group generation storage contract body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'group generation storage contract installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_access_label_freshness_storage_v1() IS DISTINCT FROM true
        OR kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'group generation storage contract storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage_contract$;
-- +goose StatementEnd
