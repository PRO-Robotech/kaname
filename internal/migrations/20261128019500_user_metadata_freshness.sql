-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- BEFORE, AFTER и проверка результата читают одно финальное решение владельца.
-- Scope доступа и выбор координат уже подтверждены при записи approved_at.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_freshness_command_v1()
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $command$
DECLARE
    proof jsonb;
    program jsonb;
    saved jsonb;
    images jsonb;
    cmd jsonb;
    origin jsonb;
    physical jsonb;
    receipt jsonb;
    uid text;
    decided timestamptz;
    staged timestamptz;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    proof:=kaname.authority_protocol_attestation();
    program:=kaname._authority_sequence_store_v3();
    cmd:=program->'frozen';
    saved:=kaname._authority_metadata_access_label_stashed_v1();
    images:=saved->'user_images';
    uid:=images->>'root_id';
    origin:=cmd#>'{effects,maximum,0,origin}';
    physical:=cmd->'access_label_root_physical';
    receipt:=cmd->'access_label_freshness';
    staged:=(program->>'staged_decision_at')::timestamptz;
    decided:=(program->>'decision_at')::timestamptz;
    IF proof->>'mode' IS DISTINCT FROM 'global' OR proof->>'kind' IS DISTINCT FROM 'resource'
        OR proof->>'writer_contract' IS DISTINCT FROM '2' OR proof->>'purpose' IS DISTINCT FROM 'decision'
        OR nullif(proof->>'nonce','') IS NULL OR program->'nonce' IS DISTINCT FROM proof->'nonce'
        OR images->'nonce' IS DISTINCT FROM proof->'nonce' OR saved->'user_protected_reserved' IS DISTINCT FROM proof->'nonce'
        OR decided IS NULL OR NOT isfinite(decided) OR staged IS NULL OR NOT isfinite(staged) OR decided<=staged
        OR decided IS DISTINCT FROM (proof->>'decision_at')::timestamptz
        OR cmd->'access_label_approved_at' IS DISTINCT FROM program->'decision_at'
        OR program->>'family' IS DISTINCT FROM 'metadata' OR program->>'frozen_mode' IS DISTINCT FROM 'user_access_labels'
        OR cmd->>'kind' IS DISTINCT FROM 'metadata.user.access_labels' OR cmd->>'mode' IS DISTINCT FROM 'user_access_labels'
        OR program->>'maximum_count' IS DISTINCT FROM '1' OR program->>'selected_count' IS DISTINCT FROM '1'
        OR images->>'mode' IS DISTINCT FROM 'access_labels' OR cmd->'question' IS DISTINCT FROM images->'update_question'
        OR coalesce(uid,'') COLLATE "C" !~ '^usr[a-zA-Z0-9_-]{1,61}$'
        OR nullif(physical->>'xmin','') IS NULL OR nullif(physical->>'ctid','') IS NULL
        OR physical IS DISTINCT FROM jsonb_build_object('table','users','id',uid,'xmin',physical->>'xmin','ctid',physical->>'ctid')
        OR physical IS DISTINCT FROM images->'root_physical'
        OR origin IS DISTINCT FROM jsonb_build_object('table','users','operation','UPDATE','when','AFTER',
            'old',images->'old_row','new',images->'new_row')
        OR program#>'{maximum,0,origin}' IS DISTINCT FROM origin OR program#>'{selected,0,origin}' IS DISTINCT FROM origin
        OR origin#>>'{old,id}' IS DISTINCT FROM uid OR origin#>>'{new,id}' IS DISTINCT FROM uid
        OR ((origin->'old')-ARRAY['access_labels','labels']) IS DISTINCT FROM ((origin->'new')-ARRAY['access_labels','labels'])
        OR origin#>'{old,access_labels}' IS NOT DISTINCT FROM origin#>'{new,access_labels}'
        OR receipt->>'root_type' IS DISTINCT FROM 'iam.user' OR receipt->>'root_id' IS DISTINCT FROM uid
        OR receipt->'old_labels' IS DISTINCT FROM origin#>'{old,access_labels}'
        OR receipt->'new_labels' IS DISTINCT FROM origin#>'{new,access_labels}'
        OR NOT (receipt ? 'prior_generation') OR jsonb_typeof(receipt->'facts') IS DISTINCT FROM 'array'
        OR jsonb_array_length(receipt->'facts')>100000 THEN
        RAISE EXCEPTION 'user freshness requires the exact approved root and decision' USING ERRCODE='42501';
    END IF;
    RETURN jsonb_build_object('nonce',proof->'nonce','origin',origin,'physical',physical,'freshness',receipt,
        'phase',cmd->'phase','installed',cmd ? 'access_label_freshness_installed','marker',cmd->'access_label_freshness_installed');
END;
$command$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_trigger_v1(
    p_rel oid,p_name text,p_timing text,p_old jsonb,p_new jsonb,p_xmin text,p_ctid text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $trigger$
DECLARE
    cmd jsonb;
    expected_new jsonb;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF pg_trigger_depth()<>1 OR p_rel IS DISTINCT FROM 'kaname.users'::regclass::oid
        OR (p_timing,p_name) IS DISTINCT FROM ('BEFORE'::text,'access_labels_immutable'::text)
        AND (p_timing,p_name) IS DISTINCT FROM ('AFTER'::text,'access_labels_000_commit_freshness'::text) THEN
        RAISE EXCEPTION 'user access label trigger context differs' USING ERRCODE='42501';
    END IF;
    cmd:=kaname._authority_metadata_user_freshness_command_v1();
    expected_new:=cmd#>'{origin,new}';
    -- PostgreSQL вычисляет STORED-колонку после BEFORE. AFTER сверяет её полное значение.
    IF p_timing='BEFORE' THEN
        expected_new:=expected_new||jsonb_build_object('expected_login_kind',NULL);
    END IF;
    IF cmd->>'phase' IS DISTINCT FROM 'writing' OR cmd->'installed' IS DISTINCT FROM 'false'::jsonb
        OR p_old IS DISTINCT FROM cmd#>'{origin,old}' OR p_new IS DISTINCT FROM expected_new
        OR p_xmin IS DISTINCT FROM cmd#>>'{physical,xmin}' OR p_ctid IS DISTINCT FROM cmd#>>'{physical,ctid}'
        OR NOT EXISTS(SELECT FROM pg_temp.kaname_authority_sequence_effects e
            WHERE e.nonce=(cmd->>'nonce')::uuid AND e.ordinal=1 AND e.table_name='resource_journal'
                AND e.origin=cmd->'origin' AND e.selected AND NOT (e.registered OR e.claimed OR e.consumed)) THEN
        RAISE EXCEPTION 'user mutation differs from the approved pending physical update' USING ERRCODE='42501';
    END IF;
    RETURN cmd->'origin';
END;
$trigger$;
-- +goose StatementEnd

-- Проверяем сохранённые координаты повторно после DML и при завершении
-- транзакции. Для пустого списка исходящих координат корень остаётся чистым.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_freshness_assert_v1()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $assert$
DECLARE
    cmd jsonb;
    receipt jsonb;
    expected integer;
    gen uuid;
    uid text;
    actual uuid;
    labels jsonb;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    cmd:=kaname._authority_metadata_user_freshness_command_v1();
    receipt:=cmd->'freshness';
    expected:=jsonb_array_length(receipt->'facts');
    gen:=(cmd->>'nonce')::uuid;
    uid:=receipt->>'root_id';
    IF coalesce(cmd->>'phase','') NOT IN ('writing','written','done')
        OR cmd->'installed' IS DISTINCT FROM 'true'::jsonb OR cmd->'marker' IS DISTINCT FROM cmd->'nonce' THEN
        RAISE EXCEPTION 'user freshness installation was not recorded' USING ERRCODE='42501';
    END IF;
    SELECT d.generation,d.new_labels INTO actual,labels FROM ONLY kaname.authority_access_label_dirty_root d
    WHERE d.root_type='iam.user' AND d.root_id=uid;
    IF expected=0 THEN
        IF FOUND THEN
            RAISE EXCEPTION 'clean user freshness has a pending generation' USING ERRCODE='40001';
        END IF;
        RETURN;
    END IF;
    IF actual IS DISTINCT FROM gen OR labels IS DISTINCT FROM receipt->'new_labels' THEN
        RAISE EXCEPTION 'user freshness root differs from installed generation' USING ERRCODE='40001';
    END IF;
    IF EXISTS(WITH actual_facts AS MATERIALIZED (
        SELECT f.object_type,f.object_id,f.relation,f.subject FROM ONLY kaname.authority_access_label_dirty_fact f
        WHERE f.root_type='iam.user' AND f.root_id=uid AND f.generation=gen LIMIT (expected+1)
    ), expected_facts AS MATERIALIZED (
        SELECT * FROM jsonb_to_recordset(receipt->'facts') f(object_type text,object_id text,relation text,subject text)
    )
    (SELECT * FROM actual_facts EXCEPT ALL SELECT * FROM expected_facts)
    UNION ALL (SELECT * FROM expected_facts EXCEPT ALL SELECT * FROM actual_facts)) THEN
        RAISE EXCEPTION 'user freshness facts differ from installed generation' USING ERRCODE='40001';
    END IF;
END;
$assert$;
-- +goose StatementEnd

-- Специализация штатной установки поколения, включая перенос всех прежних
-- координат. Исходный общий триггер и его ABI нужны предыдущим бинарным клиентам.
-- +goose StatementBegin
DO $freshness$
DECLARE src text; change jsonb;
BEGIN
    SELECT p.prosrc INTO STRICT src FROM pg_catalog.pg_proc p
    WHERE p.oid='kaname._authority_metadata_access_label_freshness_v1()'::regprocedure AND p.proowner=current_user::regrole;
    IF encode(sha256(convert_to(src,'UTF8')),'hex')<>'63c255a81eb0a63397307671b06f1279a493899018ce54bc924fc19bbf35c5c6' THEN
        RAISE EXCEPTION 'user freshness storage predecessor differs' USING ERRCODE='55000';
    END IF;
    FOR change IN SELECT value FROM jsonb_array_elements($changes$[
 [
  " move_root jsonb;\n",
  ""
 ],
 [
  "TG_TABLE_NAME NOT IN ('accounts','projects','service_accounts','resource_mirror','groups')",
  "TG_TABLE_NAME<>'users'"
 ],
 [
  " IF TG_TABLE_NAME<>'groups' THEN\n  move_root:=kaname._authority_role_move_root_trigger_v1(TG_RELID,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text);\n END IF;\n IF TG_TABLE_NAME='groups' THEN\n  command:=kaname._authority_metadata_group_trigger_v1(TG_RELID,TG_NAME,TG_WHEN,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text);\n ELSIF move_root IS NOT NULL THEN\n  command:=move_root;\n ELSIF TG_TABLE_NAME='resource_mirror' THEN\n  command:=kaname._authority_metadata_mirror_command_v1()#>'{frozen,mirror_command}';\n  IF command IS NULL OR TG_RELID<>'kaname.resource_mirror'::regclass\n   OR command#>>'{identity,dotted}' IS DISTINCT FROM OLD.object_type\n   OR command#>>'{identity,id}' IS DISTINCT FROM OLD.object_id THEN\n   RAISE EXCEPTION 'external metadata trigger lacks exact approved command' USING ERRCODE='42501';END IF;\n ELSE\n  command:=kaname._authority_metadata_access_label_origin_v1(TG_TABLE_NAME,OLD.id);\n END IF;\n",
  " command:=kaname._authority_metadata_user_trigger_v1(TG_RELID,TG_NAME,TG_WHEN,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text);\n"
 ],
 [
  "CASE WHEN move_root IS NULL THEN store#>'{frozen,access_label_freshness}' ELSE move_root->'freshness' END",
  "store#>'{frozen,access_label_freshness}'"
 ],
 [
  " OR coalesce(move_root ? 'installed',false)",
  ""
 ],
 [
  " IF move_root IS NULL THEN\n  UPDATE pg_temp.kaname_authority_sequence_program p\n  SET frozen=p.frozen||jsonb_build_object('access_label_freshness_installed',v_generation)\n  WHERE p.singleton AND p.nonce=v_generation AND p.family='metadata' AND p.frozen=store->'frozen';\n  GET DIAGNOSTICS affected=ROW_COUNT;\n ELSE\n  UPDATE pg_temp.kaname_authority_sequence_program p\n  SET frozen=jsonb_set(p.frozen,'{selector_move_active,installed}',to_jsonb(v_generation))\n  WHERE p.singleton AND p.nonce=v_generation AND p.family='role' AND p.frozen->'selector_move_active'=move_root;\n  GET DIAGNOSTICS affected=ROW_COUNT;\n END IF;\n",
  "  UPDATE pg_temp.kaname_authority_sequence_program p\n  SET frozen=p.frozen||jsonb_build_object('access_label_freshness_installed',v_generation)\n  WHERE p.singleton AND p.nonce=v_generation AND p.family='metadata' AND p.frozen=store->'frozen';\n  GET DIAGNOSTICS affected=ROW_COUNT;\n"
 ]
]$changes$::jsonb) LOOP
        IF octet_length(src)-octet_length(replace(src,change->>0,''))<>octet_length(change->>0) THEN
            RAISE EXCEPTION 'user freshness storage anchor differs' USING ERRCODE='55000';
        END IF;
        src:=replace(src,change->>0,change->>1);
    END LOOP;
    IF encode(sha256(convert_to(src,'UTF8')),'hex')<>'cae7faa2799cf717dcd71a30c3c37a2eade81389278dcce5ced244297a26eb91' THEN
        RAISE EXCEPTION 'user freshness installation body differs' USING ERRCODE='55000';
    END IF;
    EXECUTE format('CREATE FUNCTION kaname._authority_metadata_user_access_label_freshness_v1() RETURNS trigger LANGUAGE plpgsql
        VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS %L',src);
END;
$freshness$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure; recipient record;
BEGIN
    FOREACH fn IN ARRAY ARRAY[
        'kaname._authority_metadata_user_freshness_command_v1()'::regprocedure,
        'kaname._authority_metadata_user_trigger_v1(oid,text,text,jsonb,jsonb,text,text)'::regprocedure,
        'kaname._authority_metadata_user_freshness_assert_v1()'::regprocedure,
        'kaname._authority_metadata_user_access_label_freshness_v1()'::regprocedure
    ] LOOP
        FOR recipient IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE p.oid=fn AND a.grantee<>p.proowner
        LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
                CASE WHEN recipient.grantee=0 THEN 'PUBLIC' ELSE quote_ident(recipient.rolname) END);
        END LOOP;
    END LOOP;
END;
$private$;
-- +goose StatementEnd

CREATE TRIGGER access_labels_000_commit_freshness AFTER UPDATE ON kaname.users
FOR EACH ROW WHEN (OLD.access_labels IS DISTINCT FROM NEW.access_labels)
EXECUTE FUNCTION kaname._authority_metadata_user_access_label_freshness_v1();

-- +goose StatementBegin
DO $storage_contract$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
    ('access_labels_immutable_v1()','16b35a4968271c58e6eaadcee5f1f181e682abdbe21a31ea434cea268f3f153a','5785f1e5c6f6c7a3fc6691abd18f5b19eb1ab10776ba3f005ac9268fb3e1aef3',
    $changes$[
 [
  "TG_TABLE_NAME NOT IN ('accounts','projects','service_accounts','resource_mirror','groups')",
  "TG_TABLE_NAME NOT IN ('accounts','projects','service_accounts','resource_mirror','groups','users')"
 ],
 [
  " IF TG_TABLE_NAME='groups' THEN",
  " IF TG_TABLE_NAME='users' THEN\n  PERFORM kaname._authority_metadata_user_trigger_v1(TG_RELID,TG_NAME,TG_WHEN,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text);\n  RETURN NEW;\n END IF;\n IF TG_TABLE_NAME='groups' THEN"
 ]
]$changes$::jsonb),
    ('authority_access_label_storage_valid_v1()','386496cce2788809e1e66715a31b93285c2533e411a72b606e5c6e9063d9d7c2','2677e3402d1966ac473c6b2253977f9b04af4d854957a7c976da1736fde40c90',
    $changes$[
 [
  "16b35a4968271c58e6eaadcee5f1f181e682abdbe21a31ea434cea268f3f153a",
  "5785f1e5c6f6c7a3fc6691abd18f5b19eb1ab10776ba3f005ac9268fb3e1aef3"
 ],
 [
  " END LOOP;\n RETURN true;",
  " END LOOP;\n  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t\n   WHERE t.tgrelid='kaname.users'::regclass AND t.tgname='access_labels_000_commit_freshness'\n    AND t.tgfoid=to_regprocedure('kaname._authority_metadata_user_access_label_freshness_v1()')\n    AND t.tgtype=17 AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgnargs=0 AND t.tgattr=''::int2vector\n    AND t.tgconstraint=0 AND NOT t.tgdeferrable AND NOT t.tginitdeferred\n    AND pg_catalog.pg_get_triggerdef(t.oid) LIKE '% WHEN ((old.access_labels IS DISTINCT FROM new.access_labels)) EXECUTE FUNCTION %')\n  THEN RETURN false;END IF;\n RETURN true;"
 ]
]$changes$::jsonb),
    ('_authority_crud_storage_v3()','062e05901521412fe88a90ae49d1d6d6a9a8bbf543b6db5cf60ecbecc321232e','9c8b0e194eae5a26005afefdee13d5500dbba464464891be6353660a9c7a9517',
    $changes$[
 [
  "16b35a4968271c58e6eaadcee5f1f181e682abdbe21a31ea434cea268f3f153a",
  "5785f1e5c6f6c7a3fc6691abd18f5b19eb1ab10776ba3f005ac9268fb3e1aef3"
 ],
 [
  " ('_authority_metadata_group_trigger_v1(oid,text,text,jsonb,jsonb,text,text)','d93726479a48982fdc6fd435d5c00ac997eea17bf59183a79a5ab594745227aa',false,'v',true,'private'),",
  " ('_authority_metadata_group_trigger_v1(oid,text,text,jsonb,jsonb,text,text)','d93726479a48982fdc6fd435d5c00ac997eea17bf59183a79a5ab594745227aa',false,'v',true,'private'),\n ('_authority_metadata_user_freshness_command_v1()','4ec5d2c0c6798e3c70c7aeb58b791c26359f2e50a0c346a5d06db22f4fe20d98',false,'v',true,'private'),\n ('_authority_metadata_user_trigger_v1(oid,text,text,jsonb,jsonb,text,text)','e3b014dee3fb4e0ef31809d9ab7f70772b9079bda4bcd7e2b6c539dbc4662d36',false,'v',true,'private'),\n ('_authority_metadata_user_freshness_assert_v1()','0ce926ffece76d7c1c7fffe31a540f65bad7110fe419e743336126c0d3e3d670',false,'v',true,'private'),\n ('_authority_metadata_user_access_label_freshness_v1()','cae7faa2799cf717dcd71a30c3c37a2eade81389278dcce5ced244297a26eb91',false,'v',true,'private'),"
 ],
 [
  "  ('_authority_metadata_group_trigger_v1(oid,text,text,jsonb,jsonb,text,text)','jsonb',7,ARRAY['p_rel','p_name','p_timing','p_old','p_new','p_xmin','p_ctid']),",
  "  ('_authority_metadata_group_trigger_v1(oid,text,text,jsonb,jsonb,text,text)','jsonb',7,ARRAY['p_rel','p_name','p_timing','p_old','p_new','p_xmin','p_ctid']),\n  ('_authority_metadata_user_freshness_command_v1()','jsonb',0,NULL::text[]),\n  ('_authority_metadata_user_trigger_v1(oid,text,text,jsonb,jsonb,text,text)','jsonb',7,ARRAY['p_rel','p_name','p_timing','p_old','p_new','p_xmin','p_ctid']),\n  ('_authority_metadata_user_freshness_assert_v1()','void',0,NULL::text[]),\n  ('_authority_metadata_user_access_label_freshness_v1()','trigger',0,NULL::text[]),"
 ]
]$changes$::jsonb),
    ('_authority_full_contract_storage_v3()','47b4241863863490367dc274ce447fd24f25eb0b98f19f35d6551b9ac554a2c0','2c00e0a72c2a67f7237ce070dd85a881f8dfdfcef87d6ea7cfb7a30b3314da0e',
    $changes$[
 [
  "062e05901521412fe88a90ae49d1d6d6a9a8bbf543b6db5cf60ecbecc321232e",
  "9c8b0e194eae5a26005afefdee13d5500dbba464464891be6353660a9c7a9517"
 ]
]$changes$::jsonb),
    ('authority_metadata_service_account_access_label_ready_v1()','b1a32f4007d0f2c2d2b87f1de8f95d9ac6d9008a32437d5339b2bd0e34bc9843','b8d5978799639c50c4973ced399f48c4df7069a035620deda78a5b66816f12f6',
    $changes$[
 [
  "16b35a4968271c58e6eaadcee5f1f181e682abdbe21a31ea434cea268f3f153a",
  "5785f1e5c6f6c7a3fc6691abd18f5b19eb1ab10776ba3f005ac9268fb3e1aef3"
 ],
 [
  "386496cce2788809e1e66715a31b93285c2533e411a72b606e5c6e9063d9d7c2",
  "2677e3402d1966ac473c6b2253977f9b04af4d854957a7c976da1736fde40c90"
 ],
 [
  "062e05901521412fe88a90ae49d1d6d6a9a8bbf543b6db5cf60ecbecc321232e",
  "9c8b0e194eae5a26005afefdee13d5500dbba464464891be6353660a9c7a9517"
 ],
 [
  "47b4241863863490367dc274ce447fd24f25eb0b98f19f35d6551b9ac554a2c0",
  "2c00e0a72c2a67f7237ce070dd85a881f8dfdfcef87d6ea7cfb7a30b3314da0e"
 ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'user metadata trigger contract predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'user metadata trigger contract replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'user metadata trigger contract body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'user metadata trigger contract installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_access_label_freshness_storage_v1() IS DISTINCT FROM true
        OR kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'user metadata trigger contract storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage_contract$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
DROP TRIGGER access_labels_000_commit_freshness ON kaname.users;

-- +goose StatementBegin
DO $storage_contract$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
    ('authority_metadata_service_account_access_label_ready_v1()','b8d5978799639c50c4973ced399f48c4df7069a035620deda78a5b66816f12f6','b1a32f4007d0f2c2d2b87f1de8f95d9ac6d9008a32437d5339b2bd0e34bc9843',
    $changes$[
 [
  "2c00e0a72c2a67f7237ce070dd85a881f8dfdfcef87d6ea7cfb7a30b3314da0e",
  "47b4241863863490367dc274ce447fd24f25eb0b98f19f35d6551b9ac554a2c0"
 ],
 [
  "9c8b0e194eae5a26005afefdee13d5500dbba464464891be6353660a9c7a9517",
  "062e05901521412fe88a90ae49d1d6d6a9a8bbf543b6db5cf60ecbecc321232e"
 ],
 [
  "2677e3402d1966ac473c6b2253977f9b04af4d854957a7c976da1736fde40c90",
  "386496cce2788809e1e66715a31b93285c2533e411a72b606e5c6e9063d9d7c2"
 ],
 [
  "5785f1e5c6f6c7a3fc6691abd18f5b19eb1ab10776ba3f005ac9268fb3e1aef3",
  "16b35a4968271c58e6eaadcee5f1f181e682abdbe21a31ea434cea268f3f153a"
 ]
]$changes$::jsonb),
    ('_authority_full_contract_storage_v3()','2c00e0a72c2a67f7237ce070dd85a881f8dfdfcef87d6ea7cfb7a30b3314da0e','47b4241863863490367dc274ce447fd24f25eb0b98f19f35d6551b9ac554a2c0',
    $changes$[
 [
  "9c8b0e194eae5a26005afefdee13d5500dbba464464891be6353660a9c7a9517",
  "062e05901521412fe88a90ae49d1d6d6a9a8bbf543b6db5cf60ecbecc321232e"
 ]
]$changes$::jsonb),
    ('_authority_crud_storage_v3()','9c8b0e194eae5a26005afefdee13d5500dbba464464891be6353660a9c7a9517','062e05901521412fe88a90ae49d1d6d6a9a8bbf543b6db5cf60ecbecc321232e',
    $changes$[
 [
  "  ('_authority_metadata_group_trigger_v1(oid,text,text,jsonb,jsonb,text,text)','jsonb',7,ARRAY['p_rel','p_name','p_timing','p_old','p_new','p_xmin','p_ctid']),\n  ('_authority_metadata_user_freshness_command_v1()','jsonb',0,NULL::text[]),\n  ('_authority_metadata_user_trigger_v1(oid,text,text,jsonb,jsonb,text,text)','jsonb',7,ARRAY['p_rel','p_name','p_timing','p_old','p_new','p_xmin','p_ctid']),\n  ('_authority_metadata_user_freshness_assert_v1()','void',0,NULL::text[]),\n  ('_authority_metadata_user_access_label_freshness_v1()','trigger',0,NULL::text[]),",
  "  ('_authority_metadata_group_trigger_v1(oid,text,text,jsonb,jsonb,text,text)','jsonb',7,ARRAY['p_rel','p_name','p_timing','p_old','p_new','p_xmin','p_ctid']),"
 ],
 [
  " ('_authority_metadata_group_trigger_v1(oid,text,text,jsonb,jsonb,text,text)','d93726479a48982fdc6fd435d5c00ac997eea17bf59183a79a5ab594745227aa',false,'v',true,'private'),\n ('_authority_metadata_user_freshness_command_v1()','4ec5d2c0c6798e3c70c7aeb58b791c26359f2e50a0c346a5d06db22f4fe20d98',false,'v',true,'private'),\n ('_authority_metadata_user_trigger_v1(oid,text,text,jsonb,jsonb,text,text)','e3b014dee3fb4e0ef31809d9ab7f70772b9079bda4bcd7e2b6c539dbc4662d36',false,'v',true,'private'),\n ('_authority_metadata_user_freshness_assert_v1()','0ce926ffece76d7c1c7fffe31a540f65bad7110fe419e743336126c0d3e3d670',false,'v',true,'private'),\n ('_authority_metadata_user_access_label_freshness_v1()','cae7faa2799cf717dcd71a30c3c37a2eade81389278dcce5ced244297a26eb91',false,'v',true,'private'),",
  " ('_authority_metadata_group_trigger_v1(oid,text,text,jsonb,jsonb,text,text)','d93726479a48982fdc6fd435d5c00ac997eea17bf59183a79a5ab594745227aa',false,'v',true,'private'),"
 ],
 [
  "5785f1e5c6f6c7a3fc6691abd18f5b19eb1ab10776ba3f005ac9268fb3e1aef3",
  "16b35a4968271c58e6eaadcee5f1f181e682abdbe21a31ea434cea268f3f153a"
 ]
]$changes$::jsonb),
    ('authority_access_label_storage_valid_v1()','2677e3402d1966ac473c6b2253977f9b04af4d854957a7c976da1736fde40c90','386496cce2788809e1e66715a31b93285c2533e411a72b606e5c6e9063d9d7c2',
    $changes$[
 [
  " END LOOP;\n  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t\n   WHERE t.tgrelid='kaname.users'::regclass AND t.tgname='access_labels_000_commit_freshness'\n    AND t.tgfoid=to_regprocedure('kaname._authority_metadata_user_access_label_freshness_v1()')\n    AND t.tgtype=17 AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgnargs=0 AND t.tgattr=''::int2vector\n    AND t.tgconstraint=0 AND NOT t.tgdeferrable AND NOT t.tginitdeferred\n    AND pg_catalog.pg_get_triggerdef(t.oid) LIKE '% WHEN ((old.access_labels IS DISTINCT FROM new.access_labels)) EXECUTE FUNCTION %')\n  THEN RETURN false;END IF;\n RETURN true;",
  " END LOOP;\n RETURN true;"
 ],
 [
  "5785f1e5c6f6c7a3fc6691abd18f5b19eb1ab10776ba3f005ac9268fb3e1aef3",
  "16b35a4968271c58e6eaadcee5f1f181e682abdbe21a31ea434cea268f3f153a"
 ]
]$changes$::jsonb),
    ('access_labels_immutable_v1()','5785f1e5c6f6c7a3fc6691abd18f5b19eb1ab10776ba3f005ac9268fb3e1aef3','16b35a4968271c58e6eaadcee5f1f181e682abdbe21a31ea434cea268f3f153a',
    $changes$[
 [
  " IF TG_TABLE_NAME='users' THEN\n  PERFORM kaname._authority_metadata_user_trigger_v1(TG_RELID,TG_NAME,TG_WHEN,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text);\n  RETURN NEW;\n END IF;\n IF TG_TABLE_NAME='groups' THEN",
  " IF TG_TABLE_NAME='groups' THEN"
 ],
 [
  "TG_TABLE_NAME NOT IN ('accounts','projects','service_accounts','resource_mirror','groups','users')",
  "TG_TABLE_NAME NOT IN ('accounts','projects','service_accounts','resource_mirror','groups')"
 ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'user metadata trigger contract predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'user metadata trigger contract replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'user metadata trigger contract body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'user metadata trigger contract installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_access_label_freshness_storage_v1() IS DISTINCT FROM true
        OR kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'user metadata trigger contract storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage_contract$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_metadata_user_access_label_freshness_v1();
DROP FUNCTION kaname._authority_metadata_user_freshness_assert_v1();
DROP FUNCTION kaname._authority_metadata_user_trigger_v1(oid,text,text,jsonb,jsonb,text,text);
DROP FUNCTION kaname._authority_metadata_user_freshness_command_v1();
