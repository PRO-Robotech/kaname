-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- Проверка на том же соединении после барьера подтверждает только последнюю
-- ревизию. Содержимое и история журнала остаются у владельца.
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_role_actor_publication_matches_v1(p_revision bigint,p_digest text,p_catalog text)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $pair$
BEGIN
 IF kaname._authority_role_actor_login_current_v1() IS NULL OR pg_catalog.pg_is_in_recovery() THEN
  RETURN false;
 END IF;
 IF p_revision IS NULL OR p_digest IS NULL OR p_catalog IS NULL THEN RETURN false;END IF;
 RETURN coalesce((
  SELECT p.revision=p_revision AND p.digest=p_digest AND p.catalog_id=p_catalog
  FROM kaname.publication_model_revision p ORDER BY p.revision DESC LIMIT 1
 ),p_revision=0) IS TRUE;
END;
$pair$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $seat$
DECLARE
    fn regprocedure:='kaname.authority_role_actor_publication_matches_v1(bigint,text,text)'::regprocedure;
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
DO $publication_contract$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('authority_role_actor_grant_v1(regrole)','f274240b1f71a9e30882bf57eea3d0aabc0a0dd4a5978a0e0863f20a99139286','4b65f74db5a4fdd556f70ac3ede83713025f7e6c1bf5123b8e90eae6d42b095d',$changes$[
 [
  "'authority_role_actor_pair_ready_v1(oid,text)'",
  "'authority_role_actor_pair_ready_v1(oid,text)','authority_role_actor_publication_matches_v1(bigint,text,text)'"
 ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','9f1173316d540c2f9d0154cf4ef477517744938a7f6ce90ddae679b6fd944e2f','9e2f66aec8cb66f81ffa9a48324818717ad41e633e845c8603eff54602309e78',$changes$[
 [
  "f274240b1f71a9e30882bf57eea3d0aabc0a0dd4a5978a0e0863f20a99139286",
  "4b65f74db5a4fdd556f70ac3ede83713025f7e6c1bf5123b8e90eae6d42b095d"
 ],
 [
  " ('authority_role_move_enrolled_finish_v1(jsonb,integer,integer)','2421cff1eaeb06a585e12505fe38f8e636698a5977dd1e176f49b2b120c7d0c4',true,'v',true,'role_login'),",
  " ('authority_role_move_enrolled_finish_v1(jsonb,integer,integer)','2421cff1eaeb06a585e12505fe38f8e636698a5977dd1e176f49b2b120c7d0c4',true,'v',true,'role_login'),\n ('authority_role_actor_publication_matches_v1(bigint,text,text)','2ad1415663233a01ad1ef0af54a3502ecaedb66941e3f005473f7cb9e8d243ba',true,'s',true,'role_login'),"
 ],
 [
  "  ('authority_role_move_enrolled_finish_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),",
  "  ('authority_role_move_enrolled_finish_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n  ('authority_role_actor_publication_matches_v1(bigint,text,text)','boolean',3,ARRAY['p_revision','p_digest','p_catalog']),"
 ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','9114e97740cddd10d35f8a7d3ebead804d04e5e47d4edb9998a7af038676ab00','c2f591a96b9a63b616ba4c29b41f9a738bbaa61647f5c6a5b900674ecd747318',$changes$[
 [
  "9f1173316d540c2f9d0154cf4ef477517744938a7f6ce90ddae679b6fd944e2f",
  "9e2f66aec8cb66f81ffa9a48324818717ad41e633e845c8603eff54602309e78"
 ]
]$changes$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','70d6047c8d21c53906dd47f6dd7d18b4205852c665898e383a732acf716d4b11','28a980e86925f9f81f38d54bd3bc34c3903d7dc3a4f5e0be010b516b2cfc74b1',$changes$[
 [
  "9f1173316d540c2f9d0154cf4ef477517744938a7f6ce90ddae679b6fd944e2f",
  "9e2f66aec8cb66f81ffa9a48324818717ad41e633e845c8603eff54602309e78"
 ],
 [
  "9114e97740cddd10d35f8a7d3ebead804d04e5e47d4edb9998a7af038676ab00",
  "c2f591a96b9a63b616ba4c29b41f9a738bbaa61647f5c6a5b900674ecd747318"
 ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'role publication confirmation contract predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'role publication confirmation contract replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'role publication confirmation contract body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'role publication confirmation contract installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'role publication confirmation contract storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$publication_contract$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
-- +goose StatementBegin
DO $publication_contract$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('authority_metadata_service_account_access_label_ready_v1()','28a980e86925f9f81f38d54bd3bc34c3903d7dc3a4f5e0be010b516b2cfc74b1','70d6047c8d21c53906dd47f6dd7d18b4205852c665898e383a732acf716d4b11',$changes$[
 [
  "c2f591a96b9a63b616ba4c29b41f9a738bbaa61647f5c6a5b900674ecd747318",
  "9114e97740cddd10d35f8a7d3ebead804d04e5e47d4edb9998a7af038676ab00"
 ],
 [
  "9e2f66aec8cb66f81ffa9a48324818717ad41e633e845c8603eff54602309e78",
  "9f1173316d540c2f9d0154cf4ef477517744938a7f6ce90ddae679b6fd944e2f"
 ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','c2f591a96b9a63b616ba4c29b41f9a738bbaa61647f5c6a5b900674ecd747318','9114e97740cddd10d35f8a7d3ebead804d04e5e47d4edb9998a7af038676ab00',$changes$[
 [
  "9e2f66aec8cb66f81ffa9a48324818717ad41e633e845c8603eff54602309e78",
  "9f1173316d540c2f9d0154cf4ef477517744938a7f6ce90ddae679b6fd944e2f"
 ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','9e2f66aec8cb66f81ffa9a48324818717ad41e633e845c8603eff54602309e78','9f1173316d540c2f9d0154cf4ef477517744938a7f6ce90ddae679b6fd944e2f',$changes$[
 [
  "  ('authority_role_move_enrolled_finish_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n  ('authority_role_actor_publication_matches_v1(bigint,text,text)','boolean',3,ARRAY['p_revision','p_digest','p_catalog']),",
  "  ('authority_role_move_enrolled_finish_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),"
 ],
 [
  " ('authority_role_move_enrolled_finish_v1(jsonb,integer,integer)','2421cff1eaeb06a585e12505fe38f8e636698a5977dd1e176f49b2b120c7d0c4',true,'v',true,'role_login'),\n ('authority_role_actor_publication_matches_v1(bigint,text,text)','2ad1415663233a01ad1ef0af54a3502ecaedb66941e3f005473f7cb9e8d243ba',true,'s',true,'role_login'),",
  " ('authority_role_move_enrolled_finish_v1(jsonb,integer,integer)','2421cff1eaeb06a585e12505fe38f8e636698a5977dd1e176f49b2b120c7d0c4',true,'v',true,'role_login'),"
 ],
 [
  "4b65f74db5a4fdd556f70ac3ede83713025f7e6c1bf5123b8e90eae6d42b095d",
  "f274240b1f71a9e30882bf57eea3d0aabc0a0dd4a5978a0e0863f20a99139286"
 ]
]$changes$::jsonb),
        ('authority_role_actor_grant_v1(regrole)','4b65f74db5a4fdd556f70ac3ede83713025f7e6c1bf5123b8e90eae6d42b095d','f274240b1f71a9e30882bf57eea3d0aabc0a0dd4a5978a0e0863f20a99139286',$changes$[
 [
  "'authority_role_actor_pair_ready_v1(oid,text)','authority_role_actor_publication_matches_v1(bigint,text,text)'",
  "'authority_role_actor_pair_ready_v1(oid,text)'"
 ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'role publication confirmation contract predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'role publication confirmation contract replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'role publication confirmation contract body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'role publication confirmation contract installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'role publication confirmation contract storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$publication_contract$;
-- +goose StatementEnd

DROP FUNCTION kaname.authority_role_actor_publication_matches_v1(bigint,text,text);
