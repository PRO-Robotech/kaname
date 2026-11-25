-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Свидетельство строит владелец после входа в подписанную GLOBAL decision.
-- Идентичности обеих ролей определены назначением, ни одна не приходит из RPC.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_enrollment_v1() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $enrolled$
DECLARE
    proof jsonb;
    pair kaname.authority_role_actor_login%ROWTYPE;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    proof:=kaname.authority_protocol_attestation();
    IF proof->>'mode' IS DISTINCT FROM 'global' OR proof->>'kind' IS DISTINCT FROM 'resource'
        OR proof->>'purpose' IS DISTINCT FROM 'decision' OR proof->>'writer_contract' IS DISTINCT FROM '2'
        OR proof->>'consumer_profile' IS DISTINCT FROM 'full' OR proof->>'consumer_abi' IS DISTINCT FROM '2'
        OR proof->>'nonce' IS NULL OR proof->>'invoker_oid' IS NULL THEN
        RAISE EXCEPTION 'user metadata requires a signed FULL resource decision' USING ERRCODE='42501';
    END IF;
    -- При смене LOGIN configure захватывает GLOBAL до строки назначения.
    SELECT e.* INTO pair FROM ONLY kaname.authority_role_actor_login e
    WHERE e.singleton AND e.role_oid=(proof->>'invoker_oid')::oid AND e.role_name=session_user FOR SHARE NOWAIT;
    IF NOT FOUND OR kaname.authority_role_actor_pair_ready_v1(pair.runtime_oid,pair.runtime_name::text) IS DISTINCT FROM true
        OR has_schema_privilege(pair.runtime_oid,'kaname','USAGE') IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'user metadata requires the enrolled executor and ordinary runtime' USING ERRCODE='42501';
    END IF;
    RETURN jsonb_build_object('runtime_oid',pair.runtime_oid,'runtime_name',pair.runtime_name,
        'invoker_oid',proof->'invoker_oid','invoker_name',pair.role_name,'nonce',proof->'nonce');
END;
$enrolled$;

-- Вызовы raw-методов доступны только владельцу. Без канонического prepare
-- они могут действовать исключительно в пределах собственных ACL signed invoker.
CREATE FUNCTION kaname._authority_metadata_user_write_acl_v1(p_saved jsonb,p_require_enrollment boolean) RETURNS oid
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $acl$
DECLARE receipt jsonb;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF p_require_enrollment IS FALSE AND NOT (p_saved ? 'user_enrollment') THEN
        receipt:=kaname.authority_protocol_attestation();
        IF receipt->>'invoker_oid' IS NULL OR receipt->>'nonce' IS NULL
            OR p_saved#>'{plan,nonce}' IS DISTINCT FROM receipt->'nonce'
            OR p_saved#>'{plan,invoker_oid}' IS DISTINCT FROM receipt->'invoker_oid' THEN
            RAISE EXCEPTION 'user metadata raw decision identity differs' USING ERRCODE='42501';
        END IF;
        RETURN (receipt->>'invoker_oid')::oid;
    END IF;
    receipt:=kaname._authority_metadata_user_enrollment_v1();
    IF p_saved->'user_enrollment' IS DISTINCT FROM receipt OR receipt->'nonce' IS DISTINCT FROM p_saved#>'{plan,nonce}'
        OR receipt->'invoker_oid' IS DISTINCT FROM p_saved#>'{plan,invoker_oid}' THEN
        RAISE EXCEPTION 'user metadata enrollment differs from prepared decision' USING ERRCODE='42501';
    END IF;
    RETURN (receipt->>'runtime_oid')::oid;
END;
$acl$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure; item record;
BEGIN
    FOREACH fn IN ARRAY ARRAY['kaname._authority_metadata_user_enrollment_v1()'::regprocedure,
        'kaname._authority_metadata_user_write_acl_v1(jsonb,boolean)'::regprocedure] LOOP
        FOR item IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON a.grantee=r.oid WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
                CASE WHEN item.grantee=0 THEN 'PUBLIC' ELSE format('%I',item.rolname) END);
        END LOOP;
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $transition$
DECLARE row record; fn regprocedure; original text; installed text; definition text; pair jsonb; marker text;
BEGIN
    IF EXISTS(SELECT FROM (VALUES
        ('authority_role_actor_pair_ready_v1(oid,text)','f505be6caecf533c3bb32d76e640ef84be9288e25714ee696ccc43bb0aa1ec79',true,'s'),
        ('_authority_metadata_user_enrollment_v1()','11e3150b360761978624fc4a8b9489206625b9c9ef209a98b9ef348393d75a62',false,'v'),
        ('_authority_metadata_user_write_acl_v1(jsonb,boolean)','8b7ca5f72127039c83bcf26667da160d7c7a518337419db1c0d9108f29264b7b',false,'v')
    ) x(signature,digest,definer,volatility)
    WHERE NOT EXISTS(SELECT FROM pg_catalog.pg_proc p
        WHERE p.oid=to_regprocedure('kaname.'||x.signature) AND p.proowner=current_user::regrole
            AND p.prosecdef=x.definer AND p.provolatile::text=x.volatility
            AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
            AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=x.digest)) THEN
        RAISE EXCEPTION 'user enrollment dependency differs' USING ERRCODE='55000';
    END IF;
    FOR row IN SELECT * FROM (VALUES
        ('_authority_metadata_user_target_hold_v1(text,text,integer,integer)', '1df6ba591a567e264d45e6d83b76b5813dd9cf4045623434ad782d20a0f00f65', '6f74069aa41e99c6562cae6af27134b418cf4c62a388c31fad523ab0ec959b0c',
         $edits$[
 [
  "    invoker oid;",
  "    invoker oid; ordinary_role oid; saved jsonb;"
 ],
 [
  "    target:=kaname._authority_metadata_access_label_stashed_v1()->'root';",
  "    saved:=kaname._authority_metadata_access_label_stashed_v1();\n    target:=saved->'root';"
 ],
 [
  "    invoker:=(proof->>'invoker_oid')::oid;",
  "    invoker:=(proof->>'invoker_oid')::oid;\n    ordinary_role:=kaname._authority_metadata_user_write_acl_v1(saved,false);"
 ],
 [
  "AND has_table_privilege(invoker,c.oid,'SELECT'))<>2",
  "AND has_table_privilege(invoker,c.oid,'SELECT') AND has_table_privilege(ordinary_role,c.oid,'SELECT'))<>2"
 ],
 [
  "has_column_privilege(invoker,'kaname.users','labels'",
  "has_column_privilege(ordinary_role,'kaname.users','labels'"
 ],
 [
  "has_column_privilege(invoker,'kaname.users','access_labels'",
  "has_column_privilege(ordinary_role,'kaname.users','access_labels'"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_noop_reserve_v1(text,timestamptz,bytea,text,text,text,text,integer,integer)', '9f3804647e2534539abc841df97eaff42d4107f24cb19bd05c9378a7dab60143', 'fd3bec23fd73e58697dad2668375cb0eb22a02dd06636d83d5fe5c0a85ecf41c',
         $edits$[
 [
  "invoker:=(stash#>>'{plan,invoker_oid}')::oid;",
  "invoker:=kaname._authority_metadata_user_write_acl_v1(stash,false);"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_ordinary_reserve_v1(text,timestamptz,bytea,text,text,text,text,integer,integer,text)', '5e947bed8a60334a202d41137e44a561e2f352555707d3c07fb9b87242a4c18f', '402b06e4819a8714f734afe01aefa3450d2ee65e8d635a42d30fd24faeb799fc',
         $edits$[
 [
  "invoker:=(stash#>>'{plan,invoker_oid}')::oid;",
  "invoker:=kaname._authority_metadata_user_write_acl_v1(stash,false);"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_protected_reserve_v1(text,timestamptz,bytea,text,text,text,text,integer,integer,text,jsonb,integer)', 'c526da7587930a83ecfa596f64cd20495f342493913a9aa16617a087f57bab47', '4e1d0f5d9e46cd44cb7763831f37f9b95f4e49e390090a2604450e64cfe0dad6',
         $edits$[
 [
  "invoker:=(stash#>>'{plan,invoker_oid}')::oid;",
  "invoker:=kaname._authority_metadata_user_write_acl_v1(stash,false);"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_ordinary_effects_v1(text)', '9d1cdbe9ee805b7c840b38d2b2093255abb79962b9641be74bf2ab018be8cac9', '47379e34ac5c5e0441763514d183a0ee15620d8d6ab181d83aae2613703cc386',
         $edits$[
 [
  "invoker:=(stash#>>'{plan,invoker_oid}')::oid;",
  "invoker:=kaname._authority_metadata_user_write_acl_v1(stash,false);"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_protected_effects_v1(text)', '439c54034b7f6f20e3c37a8e6db132e48cc204db3229ba0185eb1924a992ede3', 'd1ad5d32a979e48dba11f81fb8e47556dc9f9e29900fccfbbbf3b108f4d9d90b',
         $edits$[
 [
  "invoker:=(stash#>>'{plan,invoker_oid}')::oid;",
  "invoker:=kaname._authority_metadata_user_write_acl_v1(stash,false);"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_prepare_v1(text,text,text,jsonb,jsonb,jsonb,text,text,jsonb,integer,integer,integer)', 'c3d2e3bc12068cb55eee0f1239e0b461081861f2a4797ca607c080aade792bfd', '0e8b42c35b8b971968a51a65ca5f065d20234565d1fb07c43044ac7f6c1819eb',
         $edits$[
 [
  "    proof jsonb;\nBEGIN",
  "    proof jsonb;\n    enrollment jsonb;\nBEGIN\n    enrollment:=kaname._authority_metadata_user_enrollment_v1();\n    <<prepare_image>>\n    BEGIN"
 ],
 [
  "        RETURN;",
  "        EXIT prepare_image;"
 ],
 [
  "    RETURN NEXT;",
  "    RETURN NEXT;\n    END prepare_image;\n    -- Обе ветви только что создали owner-only relation через stash_v1.\n    UPDATE pg_temp.kaname_authority_metadata_discovery d\n    SET prepared=d.prepared||jsonb_build_object('user_enrollment',enrollment)\n    WHERE d.singleton AND NOT (d.prepared ? 'user_enrollment')\n        AND d.prepared#>'{plan,nonce}'=enrollment->'nonce'\n        AND d.prepared#>'{plan,invoker_oid}'=enrollment->'invoker_oid'\n        AND d.prepared#>>'{root,root_coordinate,1}'=p_id;\n    IF NOT FOUND THEN\n        RAISE EXCEPTION 'user metadata enrollment was not sealed' USING ERRCODE='42501';\n    END IF;"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_retention_inputs_v1(text,text,integer,integer,integer)', 'c670d1ac881afeccadb3675612bbfe74da3eb5ee8e8ada680b8ce16a8af52c66', '13ab4c53af8a3fe9a1c3b6a93357915b67f39bd26f896585177c6488445cfd7b',
         $edits$[
 [
  "\nBEGIN\n",
  "\nBEGIN\n    PERFORM kaname._authority_metadata_user_write_acl_v1(kaname._authority_metadata_access_label_stashed_v1(),true);\n"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_reserve_v1(text,timestamptz,bytea,text,text,text,text,text,jsonb,integer,integer,integer)', '2df9818b9af0468b63fb69f20a263832e8c0a45115a53465f56c19b8a2062e61', '06dce9b535cb7fa3b097d5d353c142547422e4671c00cd323a794d1b3b51658d',
         $edits$[
 [
  "\nBEGIN\n",
  "\nBEGIN\n    PERFORM kaname._authority_metadata_user_write_acl_v1(kaname._authority_metadata_access_label_stashed_v1(),true);\n"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_apply_v1(text,uuid,timestamptz,integer,integer,integer)', '8a40485c03b025b5aa070457a676a06813eae320a0d1e31ba23d88a0de98f870', '0edcb455fa513aeb2c08c31d65264c97c896ba77d32c66d2b97896882c5145a5',
         $edits$[
 [
  "\nBEGIN\n",
  "\nBEGIN\n    PERFORM kaname._authority_metadata_user_write_acl_v1(kaname._authority_metadata_access_label_stashed_v1(),true);\n"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_complete_v1(text,uuid,timestamptz,bytea)', '047cd56c83fa219db47456b80828c64b4e3c68e094f5336b3d0254d27a0ea53e', '93bb0e84a56f023a55225a560530fbe6d5ea418c16b3273442db69577feaee66',
         $edits$[
 [
  "\nBEGIN\n",
  "\nBEGIN\n    PERFORM kaname._authority_metadata_user_write_acl_v1(kaname._authority_metadata_access_label_stashed_v1(),true);\n"
 ]
]$edits$::jsonb)
    ) x(signature,prior,revised,edits) LOOP
        fn:=to_regprocedure('kaname.'||row.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
        FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole
            AND p.prosecdef=(left(row.signature,1)<>'_') AND p.provolatile='v'
            AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
            AND NOT EXISTS(SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee<>p.proowner);
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM row.prior THEN
            RAISE EXCEPTION 'user enrollment predecessor differs: %',row.signature USING ERRCODE='55000';
        END IF;
        installed:=original;
        FOR pair IN SELECT value FROM jsonb_array_elements(row.edits) LOOP
            IF octet_length(installed)-octet_length(replace(installed,pair->>0,''))<>octet_length(pair->>0) THEN
                RAISE EXCEPTION 'user enrollment replacement ambiguous: %',row.signature USING ERRCODE='55000';
            END IF;
            installed:=replace(installed,pair->>0,pair->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0 OR
            encode(sha256(convert_to(installed,'UTF8')),'hex') IS DISTINCT FROM row.revised THEN
            RAISE EXCEPTION 'user enrollment transition differs: %',row.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(installed));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM row.revised THEN
            RAISE EXCEPTION 'user enrollment installed body differs: %',row.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
END;
$transition$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $transition$
DECLARE row record; fn regprocedure; original text; installed text; definition text; pair jsonb; marker text;
BEGIN
    IF EXISTS(SELECT FROM (VALUES
        ('authority_role_actor_pair_ready_v1(oid,text)','f505be6caecf533c3bb32d76e640ef84be9288e25714ee696ccc43bb0aa1ec79',true,'s'),
        ('_authority_metadata_user_enrollment_v1()','11e3150b360761978624fc4a8b9489206625b9c9ef209a98b9ef348393d75a62',false,'v'),
        ('_authority_metadata_user_write_acl_v1(jsonb,boolean)','8b7ca5f72127039c83bcf26667da160d7c7a518337419db1c0d9108f29264b7b',false,'v')
    ) x(signature,digest,definer,volatility)
    WHERE NOT EXISTS(SELECT FROM pg_catalog.pg_proc p
        WHERE p.oid=to_regprocedure('kaname.'||x.signature) AND p.proowner=current_user::regrole
            AND p.prosecdef=x.definer AND p.provolatile::text=x.volatility
            AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
            AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=x.digest)) THEN
        RAISE EXCEPTION 'user enrollment dependency differs' USING ERRCODE='55000';
    END IF;
    FOR row IN SELECT * FROM (VALUES
        ('authority_metadata_user_complete_v1(text,uuid,timestamptz,bytea)', '93bb0e84a56f023a55225a560530fbe6d5ea418c16b3273442db69577feaee66', '047cd56c83fa219db47456b80828c64b4e3c68e094f5336b3d0254d27a0ea53e',
         $edits$[
 [
  "\nBEGIN\n    PERFORM kaname._authority_metadata_user_write_acl_v1(kaname._authority_metadata_access_label_stashed_v1(),true);\n",
  "\nBEGIN\n"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_apply_v1(text,uuid,timestamptz,integer,integer,integer)', '0edcb455fa513aeb2c08c31d65264c97c896ba77d32c66d2b97896882c5145a5', '8a40485c03b025b5aa070457a676a06813eae320a0d1e31ba23d88a0de98f870',
         $edits$[
 [
  "\nBEGIN\n    PERFORM kaname._authority_metadata_user_write_acl_v1(kaname._authority_metadata_access_label_stashed_v1(),true);\n",
  "\nBEGIN\n"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_reserve_v1(text,timestamptz,bytea,text,text,text,text,text,jsonb,integer,integer,integer)', '06dce9b535cb7fa3b097d5d353c142547422e4671c00cd323a794d1b3b51658d', '2df9818b9af0468b63fb69f20a263832e8c0a45115a53465f56c19b8a2062e61',
         $edits$[
 [
  "\nBEGIN\n    PERFORM kaname._authority_metadata_user_write_acl_v1(kaname._authority_metadata_access_label_stashed_v1(),true);\n",
  "\nBEGIN\n"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_retention_inputs_v1(text,text,integer,integer,integer)', '13ab4c53af8a3fe9a1c3b6a93357915b67f39bd26f896585177c6488445cfd7b', 'c670d1ac881afeccadb3675612bbfe74da3eb5ee8e8ada680b8ce16a8af52c66',
         $edits$[
 [
  "\nBEGIN\n    PERFORM kaname._authority_metadata_user_write_acl_v1(kaname._authority_metadata_access_label_stashed_v1(),true);\n",
  "\nBEGIN\n"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_prepare_v1(text,text,text,jsonb,jsonb,jsonb,text,text,jsonb,integer,integer,integer)', '0e8b42c35b8b971968a51a65ca5f065d20234565d1fb07c43044ac7f6c1819eb', 'c3d2e3bc12068cb55eee0f1239e0b461081861f2a4797ca607c080aade792bfd',
         $edits$[
 [
  "    RETURN NEXT;\n    END prepare_image;\n    -- Обе ветви только что создали owner-only relation через stash_v1.\n    UPDATE pg_temp.kaname_authority_metadata_discovery d\n    SET prepared=d.prepared||jsonb_build_object('user_enrollment',enrollment)\n    WHERE d.singleton AND NOT (d.prepared ? 'user_enrollment')\n        AND d.prepared#>'{plan,nonce}'=enrollment->'nonce'\n        AND d.prepared#>'{plan,invoker_oid}'=enrollment->'invoker_oid'\n        AND d.prepared#>>'{root,root_coordinate,1}'=p_id;\n    IF NOT FOUND THEN\n        RAISE EXCEPTION 'user metadata enrollment was not sealed' USING ERRCODE='42501';\n    END IF;",
  "    RETURN NEXT;"
 ],
 [
  "        EXIT prepare_image;",
  "        RETURN;"
 ],
 [
  "    proof jsonb;\n    enrollment jsonb;\nBEGIN\n    enrollment:=kaname._authority_metadata_user_enrollment_v1();\n    <<prepare_image>>\n    BEGIN",
  "    proof jsonb;\nBEGIN"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_protected_effects_v1(text)', 'd1ad5d32a979e48dba11f81fb8e47556dc9f9e29900fccfbbbf3b108f4d9d90b', '439c54034b7f6f20e3c37a8e6db132e48cc204db3229ba0185eb1924a992ede3',
         $edits$[
 [
  "invoker:=kaname._authority_metadata_user_write_acl_v1(stash,false);",
  "invoker:=(stash#>>'{plan,invoker_oid}')::oid;"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_ordinary_effects_v1(text)', '47379e34ac5c5e0441763514d183a0ee15620d8d6ab181d83aae2613703cc386', '9d1cdbe9ee805b7c840b38d2b2093255abb79962b9641be74bf2ab018be8cac9',
         $edits$[
 [
  "invoker:=kaname._authority_metadata_user_write_acl_v1(stash,false);",
  "invoker:=(stash#>>'{plan,invoker_oid}')::oid;"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_protected_reserve_v1(text,timestamptz,bytea,text,text,text,text,integer,integer,text,jsonb,integer)', '4e1d0f5d9e46cd44cb7763831f37f9b95f4e49e390090a2604450e64cfe0dad6', 'c526da7587930a83ecfa596f64cd20495f342493913a9aa16617a087f57bab47',
         $edits$[
 [
  "invoker:=kaname._authority_metadata_user_write_acl_v1(stash,false);",
  "invoker:=(stash#>>'{plan,invoker_oid}')::oid;"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_ordinary_reserve_v1(text,timestamptz,bytea,text,text,text,text,integer,integer,text)', '402b06e4819a8714f734afe01aefa3450d2ee65e8d635a42d30fd24faeb799fc', '5e947bed8a60334a202d41137e44a561e2f352555707d3c07fb9b87242a4c18f',
         $edits$[
 [
  "invoker:=kaname._authority_metadata_user_write_acl_v1(stash,false);",
  "invoker:=(stash#>>'{plan,invoker_oid}')::oid;"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_noop_reserve_v1(text,timestamptz,bytea,text,text,text,text,integer,integer)', 'fd3bec23fd73e58697dad2668375cb0eb22a02dd06636d83d5fe5c0a85ecf41c', '9f3804647e2534539abc841df97eaff42d4107f24cb19bd05c9378a7dab60143',
         $edits$[
 [
  "invoker:=kaname._authority_metadata_user_write_acl_v1(stash,false);",
  "invoker:=(stash#>>'{plan,invoker_oid}')::oid;"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_target_hold_v1(text,text,integer,integer)', '6f74069aa41e99c6562cae6af27134b418cf4c62a388c31fad523ab0ec959b0c', '1df6ba591a567e264d45e6d83b76b5813dd9cf4045623434ad782d20a0f00f65',
         $edits$[
 [
  "has_column_privilege(ordinary_role,'kaname.users','access_labels'",
  "has_column_privilege(invoker,'kaname.users','access_labels'"
 ],
 [
  "has_column_privilege(ordinary_role,'kaname.users','labels'",
  "has_column_privilege(invoker,'kaname.users','labels'"
 ],
 [
  "AND has_table_privilege(invoker,c.oid,'SELECT') AND has_table_privilege(ordinary_role,c.oid,'SELECT'))<>2",
  "AND has_table_privilege(invoker,c.oid,'SELECT'))<>2"
 ],
 [
  "    invoker:=(proof->>'invoker_oid')::oid;\n    ordinary_role:=kaname._authority_metadata_user_write_acl_v1(saved,false);",
  "    invoker:=(proof->>'invoker_oid')::oid;"
 ],
 [
  "    saved:=kaname._authority_metadata_access_label_stashed_v1();\n    target:=saved->'root';",
  "    target:=kaname._authority_metadata_access_label_stashed_v1()->'root';"
 ],
 [
  "    invoker oid; ordinary_role oid; saved jsonb;",
  "    invoker oid;"
 ]
]$edits$::jsonb)
    ) x(signature,prior,revised,edits) LOOP
        fn:=to_regprocedure('kaname.'||row.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
        FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole
            AND p.prosecdef=(left(row.signature,1)<>'_') AND p.provolatile='v'
            AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
            AND NOT EXISTS(SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee<>p.proowner);
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM row.prior THEN
            RAISE EXCEPTION 'user enrollment predecessor differs: %',row.signature USING ERRCODE='55000';
        END IF;
        installed:=original;
        FOR pair IN SELECT value FROM jsonb_array_elements(row.edits) LOOP
            IF octet_length(installed)-octet_length(replace(installed,pair->>0,''))<>octet_length(pair->>0) THEN
                RAISE EXCEPTION 'user enrollment replacement ambiguous: %',row.signature USING ERRCODE='55000';
            END IF;
            installed:=replace(installed,pair->>0,pair->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0 OR
            encode(sha256(convert_to(installed,'UTF8')),'hex') IS DISTINCT FROM row.revised THEN
            RAISE EXCEPTION 'user enrollment transition differs: %',row.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(installed));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM row.revised THEN
            RAISE EXCEPTION 'user enrollment installed body differs: %',row.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
END;
$transition$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_metadata_user_write_acl_v1(jsonb,boolean);
DROP FUNCTION kaname._authority_metadata_user_enrollment_v1();
