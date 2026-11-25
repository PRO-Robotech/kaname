-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Выделенный writer вызывает этот вход после RequireRole, v_update и
-- prospective Grant. Owner-функция сверяет LOGIN, изоляцию и подписанное
-- решение, затем проверяет и выбирает единственный подготовленный слот.
CREATE FUNCTION kaname.authority_role_move_enrolled_finish_v1(p_sets jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $finish$
BEGIN
    RETURN kaname.authority_role_move_pending_finalize_v1(p_sets,p_rows,p_reads);
END;
$finish$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $seat$
DECLARE
    fn regprocedure:='kaname.authority_role_move_enrolled_finish_v1(jsonb,integer,integer)'::regprocedure;
    grantee record;
    seat name;
BEGIN
    -- Убираем права из ALTER DEFAULT PRIVILEGES, включая PUBLIC, до выдачи.
    FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
        CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
            CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
    END LOOP;
    -- Накат на действующем назначении меняет только ACL нового входа.
    SELECT r.rolname INTO seat FROM kaname.authority_role_actor_login e
        JOIN pg_catalog.pg_roles r ON (r.oid,r.rolname)=(e.role_oid,e.role_name)
        JOIN pg_catalog.pg_roles shared ON (shared.oid,shared.rolname)=(e.runtime_oid,e.runtime_name)
        WHERE e.singleton AND e.role_oid<>e.runtime_oid AND kaname._authority_role_actor_ordinary_login_v1(r.oid)
        AND NOT EXISTS(SELECT FROM pg_catalog.pg_auth_members m WHERE m.roleid=r.oid);
    IF FOUND THEN
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %I',fn,seat);
    END IF;
END;
$seat$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $finish_contract$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('authority_role_actor_grant_v1(regrole)','0e490ec95c169d8352e2eca5f439d7b3bbab4a2c0667df9c0c82f212c5b8da55','2ec21ce4d50d39444e0e92ba2ae81bb885ab5fdfcf8265552ce02ddc4841f96a',$changes$[
  [
    "  'authority_role_actor_login_ready_v1()','authority_role_access_label_content_approved_v1()'",
    "  'authority_role_actor_login_ready_v1()','authority_role_access_label_content_approved_v1()',\n  'authority_role_move_enrolled_finish_v1(jsonb,integer,integer)'"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','d02583f4fbcf55384579586a637b5f0716b2d858e913995c67460bb74cf6e423','d96c861f7c4e639756685c0c1bc79ed3595e2cd67785339d57de23ba53c71983',$changes$[
  [
    "0e490ec95c169d8352e2eca5f439d7b3bbab4a2c0667df9c0c82f212c5b8da55",
    "2ec21ce4d50d39444e0e92ba2ae81bb885ab5fdfcf8265552ce02ddc4841f96a"
  ],
  [
    " ('authority_role_move_pending_finalize_v1(jsonb,integer,integer)','51ca09bef15de6ed427d20d43c358288d7623e69aa04956e79f5696be483342e',true,'v',true,'private'),\n",
    " ('authority_role_move_pending_finalize_v1(jsonb,integer,integer)','51ca09bef15de6ed427d20d43c358288d7623e69aa04956e79f5696be483342e',true,'v',true,'private'),\n ('authority_role_move_enrolled_finish_v1(jsonb,integer,integer)','2421cff1eaeb06a585e12505fe38f8e636698a5977dd1e176f49b2b120c7d0c4',true,'v',true,'role_login'),\n"
  ],
  [
    "  ('authority_role_move_pending_finalize_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n",
    "  ('authority_role_move_pending_finalize_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n  ('authority_role_move_enrolled_finish_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','50feff7af5b0a74d93cae738ba5c55efaab0ac312efb9edc13f75e0729e5ff15','e6e87e217e3323d3952cf2df43674d96eee9798fb6bd797766c583aa4ea703fe',$changes$[
  [
    "d02583f4fbcf55384579586a637b5f0716b2d858e913995c67460bb74cf6e423",
    "d96c861f7c4e639756685c0c1bc79ed3595e2cd67785339d57de23ba53c71983"
  ]
]$changes$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','53e3127bdc930b9c3b5d51b5344f47b1cdac3b668f3c222ebdff4fe2c85da732','0aed46c8be81a3e34bcb687190ea94caf7da29857b16206f76e3f7b550596f7a',$changes$[
  [
    "d02583f4fbcf55384579586a637b5f0716b2d858e913995c67460bb74cf6e423",
    "d96c861f7c4e639756685c0c1bc79ed3595e2cd67785339d57de23ba53c71983"
  ],
  [
    "50feff7af5b0a74d93cae738ba5c55efaab0ac312efb9edc13f75e0729e5ff15",
    "e6e87e217e3323d3952cf2df43674d96eee9798fb6bd797766c583aa4ea703fe"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'enrolled role finish contract predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'enrolled role finish contract replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'enrolled role finish contract body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'enrolled role finish contract installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'enrolled role finish contract storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$finish_contract$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $finish_contract$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('authority_metadata_service_account_access_label_ready_v1()','0aed46c8be81a3e34bcb687190ea94caf7da29857b16206f76e3f7b550596f7a','53e3127bdc930b9c3b5d51b5344f47b1cdac3b668f3c222ebdff4fe2c85da732',$changes$[
  [
    "e6e87e217e3323d3952cf2df43674d96eee9798fb6bd797766c583aa4ea703fe",
    "50feff7af5b0a74d93cae738ba5c55efaab0ac312efb9edc13f75e0729e5ff15"
  ],
  [
    "d96c861f7c4e639756685c0c1bc79ed3595e2cd67785339d57de23ba53c71983",
    "d02583f4fbcf55384579586a637b5f0716b2d858e913995c67460bb74cf6e423"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','e6e87e217e3323d3952cf2df43674d96eee9798fb6bd797766c583aa4ea703fe','50feff7af5b0a74d93cae738ba5c55efaab0ac312efb9edc13f75e0729e5ff15',$changes$[
  [
    "d96c861f7c4e639756685c0c1bc79ed3595e2cd67785339d57de23ba53c71983",
    "d02583f4fbcf55384579586a637b5f0716b2d858e913995c67460bb74cf6e423"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','d96c861f7c4e639756685c0c1bc79ed3595e2cd67785339d57de23ba53c71983','d02583f4fbcf55384579586a637b5f0716b2d858e913995c67460bb74cf6e423',$changes$[
  [
    "  ('authority_role_move_pending_finalize_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n  ('authority_role_move_enrolled_finish_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n",
    "  ('authority_role_move_pending_finalize_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n"
  ],
  [
    " ('authority_role_move_pending_finalize_v1(jsonb,integer,integer)','51ca09bef15de6ed427d20d43c358288d7623e69aa04956e79f5696be483342e',true,'v',true,'private'),\n ('authority_role_move_enrolled_finish_v1(jsonb,integer,integer)','2421cff1eaeb06a585e12505fe38f8e636698a5977dd1e176f49b2b120c7d0c4',true,'v',true,'role_login'),\n",
    " ('authority_role_move_pending_finalize_v1(jsonb,integer,integer)','51ca09bef15de6ed427d20d43c358288d7623e69aa04956e79f5696be483342e',true,'v',true,'private'),\n"
  ],
  [
    "2ec21ce4d50d39444e0e92ba2ae81bb885ab5fdfcf8265552ce02ddc4841f96a",
    "0e490ec95c169d8352e2eca5f439d7b3bbab4a2c0667df9c0c82f212c5b8da55"
  ]
]$changes$::jsonb),
        ('authority_role_actor_grant_v1(regrole)','2ec21ce4d50d39444e0e92ba2ae81bb885ab5fdfcf8265552ce02ddc4841f96a','0e490ec95c169d8352e2eca5f439d7b3bbab4a2c0667df9c0c82f212c5b8da55',$changes$[
  [
    "  'authority_role_actor_login_ready_v1()','authority_role_access_label_content_approved_v1()',\n  'authority_role_move_enrolled_finish_v1(jsonb,integer,integer)'",
    "  'authority_role_actor_login_ready_v1()','authority_role_access_label_content_approved_v1()'"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'enrolled role finish contract predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'enrolled role finish contract replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'enrolled role finish contract body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'enrolled role finish contract installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'enrolled role finish contract storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$finish_contract$;
-- +goose StatementEnd

DROP FUNCTION kaname.authority_role_move_enrolled_finish_v1(jsonb,integer,integer);
