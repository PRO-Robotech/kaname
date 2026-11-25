-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- NEW стороны выдачи уровня binding для роли с непустыми rules и точный
-- перечень получателей для последующей проверки её пообъектных выдач.
-- Источник — перепроверенные владельцем строки до первого DML.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_binding_new_v1(
    p_prepared jsonb,p_status jsonb,p_rows integer
) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $binding_new$
DECLARE
    census jsonb:=p_prepared->'binding_census';
    role_row jsonb:=p_prepared#>'{role,new_role}';
    role_id text:=p_prepared->>'role_id';
    used_rows integer;
    invalid boolean;
    holders jsonb;
BEGIN
    IF jsonb_typeof(census->'bindings') IS DISTINCT FROM 'array'
        OR jsonb_typeof(census->'subjects') IS DISTINCT FROM 'array'
        OR jsonb_typeof(p_status) IS DISTINCT FROM 'object'
        OR coalesce(role_id,'')='' OR role_row->>'id' IS DISTINCT FROM role_id
        OR role_row->'live' IS DISTINCT FROM 'true'::jsonb
        OR jsonb_typeof(role_row->'rules') IS DISTINCT FROM 'array'
        OR role_row->'rules'='[]'::jsonb THEN
        RAISE EXCEPTION 'selector move NEW binding inputs incomplete' USING ERRCODE='42501';
    END IF;
    IF octet_length(p_prepared::text)>8388608 OR octet_length(p_status::text)>8388608 THEN
        RAISE EXCEPTION 'selector move NEW binding inputs exceed byte budget' USING ERRCODE='54000';
    END IF;
    used_rows:=jsonb_array_length(census->'bindings')+jsonb_array_length(census->'subjects');
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000 THEN
        RAISE EXCEPTION 'selector move NEW binding rows exceed budget' USING ERRCODE='54000';
    END IF;

    -- Обратная ссылка старого участника может вести к привязке другой роли.
    -- Она остаётся в полном OLD. Новая версия этой роли к ней неприменима.
    -- Сроки и отзыв уже проверены владельцем на итоговом decision_at.
    WITH bindings AS MATERIALIZED (
        SELECT s->2 AS b,s#>>'{2,id}' AS id,p_status->>(s#>>'{2,id}') AS class
        FROM jsonb_array_elements(census->'bindings') s
    ), eligible AS MATERIALIZED (
        SELECT id,b,class FROM bindings WHERE b->>'role_id'=role_id AND class IN ('ACTIVE','PENDING')
    ), recipients AS (
        SELECT e.id,s->2 AS subject,e.b,
            s#>>'{2,subject_type}' AS typ,s#>>'{2,subject_id}' AS identifier,
            s#>>'{2,ordinal}' AS ordinal_text
        FROM jsonb_array_elements(census->'subjects') s JOIN eligible e ON e.id=s#>>'{2,binding_id}'
    ), per_binding AS (
        SELECT id,count(*) AS n,count(DISTINCT (typ,identifier)) AS distinct_n,
            bool_or(typ=b->>'subject_type' AND identifier=b->>'subject_id') AS has_primary,
            bool_and((subject->'resource_type'=b->'resource_type' AND subject->'resource_id'=b->'resource_id'
                AND typ IN ('user','group','service_account','system_class') AND octet_length(identifier) BETWEEN 1 AND 64
                AND (identifier !~ '[:#*[:space:][:cntrl:]]'
                    OR (identifier='*' AND typ='user' AND b->'is_system'='true'::jsonb))
                AND (typ<>'system_class' OR identifier IN ('anonymous','authenticated'))
                AND jsonb_typeof(subject->'ordinal')='number' AND ordinal_text ~ '^(0|[1-9][0-9]{0,9})$') IS TRUE) AS valid,
            jsonb_agg(jsonb_build_array(typ,identifier)
                ORDER BY length(ordinal_text),ordinal_text COLLATE "C",typ COLLATE "C",identifier COLLATE "C") AS subjects
        FROM recipients GROUP BY id
    )
    SELECT EXISTS(SELECT FROM bindings WHERE coalesce(class,'') NOT IN ('ACTIVE','PENDING','EXPIRED','REVOKED'))
        OR EXISTS(SELECT k FROM jsonb_object_keys(p_status) k EXCEPT SELECT id FROM bindings)
        OR coalesce(bool_or((p.n BETWEEN 1 AND 32 AND p.n=p.distinct_n AND p.has_primary AND p.valid
            AND coalesce(e.id,'')<>'' AND e.id !~ '[:#*[:space:][:cntrl:]]'
            AND e.b->>'granted_relation'='' AND jsonb_typeof(e.b->'target')='object'
            AND e.b->>'resource_id' !~ '[:#*[:space:][:cntrl:]]'
            AND CASE e.b->>'resource_type'
                WHEN 'account' THEN e.b->'scope'='2'::jsonb AND starts_with(e.b->>'resource_id','acc')
                WHEN 'project' THEN e.b->'scope'='3'::jsonb AND starts_with(e.b->>'resource_id','prj')
                WHEN 'cluster' THEN e.b->'scope'='1'::jsonb AND e.b->>'resource_id'='cluster_root'
                ELSE false END) IS NOT TRUE),false),
        coalesce(jsonb_object_agg(e.id,jsonb_build_object('class',e.class,'expires_at',e.b->'expires_at',
            'scope',jsonb_build_array(e.b->>'resource_type',e.b->>'resource_id'),'target',e.b->'target',
            'subjects',p.subjects,
            -- У правил BuildRoleTuples даёт ровно указатель на родителя. Для
            -- PENDING сохраняем получателей будущей активации без записи ребра.
            'binding_tuples',CASE WHEN e.class='ACTIVE' THEN jsonb_build_array(jsonb_build_object(
                'fga_user',(e.b->>'resource_type')||':'||(e.b->>'resource_id'),'relation',e.b->>'resource_type',
                'object','iam_access_binding:'||e.id)) ELSE '[]'::jsonb END)),'{}'::jsonb)
        INTO invalid,holders FROM eligible e LEFT JOIN per_binding p USING(id);
    IF invalid THEN RAISE EXCEPTION 'selector move NEW binding recipients or scope differ' USING ERRCODE='42501';END IF;
    IF octet_length(holders::text)>8388608 THEN
        RAISE EXCEPTION 'selector move NEW binding receipt exceeds byte budget' USING ERRCODE='54000';
    END IF;
    RETURN jsonb_build_object('holders',holders,'rows',used_rows);
END;
$binding_new$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE grantee record;fn regprocedure:='kaname._authority_role_move_binding_new_v1(jsonb,jsonb,integer)'::regprocedure;
BEGIN
    FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_proc p
        CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        LEFT JOIN pg_roles r ON r.oid=a.grantee WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
            CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $plan$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('_authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)','9e7772c3a4950497773c1e4d2dc7a0f747db4a03d08b8ac581747e50fcb43cb2','8cffc9e80a318ebb283446f57b16c6afa2deb4b06f6f075a91cf6fefcf81b273',$changes$[
 [
  "    carriers jsonb;",
  "    carriers jsonb;\n    binding_new jsonb;"
 ],
 [
  "    result:=kaname._authority_role_move_copy_requirements_require_v1",
  "    binding_new:=kaname._authority_role_move_binding_new_v1(p_frozen,carriers->'binding_status',p_rows-used_rows);\n    used_rows:=used_rows+(binding_new->>'rows')::integer;\n    result:=kaname._authority_role_move_copy_requirements_require_v1"
 ],
 [
  "'binding_status',carriers->'binding_status','rows',",
  "'binding_status',carriers->'binding_status','binding_new',binding_new->'holders','rows',"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','5808081c4afa7ccdd6b831731532c1e645aa3c7162c1c8523da497ad68da425e','707327736532ccc1a90362e3dcbccf69e4f0b86c4215fcf41cea66f972331e23',$changes$[
 [
  "9e7772c3a4950497773c1e4d2dc7a0f747db4a03d08b8ac581747e50fcb43cb2",
  "8cffc9e80a318ebb283446f57b16c6afa2deb4b06f6f075a91cf6fefcf81b273"
 ],
 [
  " ('_authority_role_move_binding_empty_require_v1(jsonb)','048b60e9637befdbbca317dba9db6d192bece6b298b1704bbcd306006b63c379',false,'v',true,'private'),",
  " ('_authority_role_move_binding_empty_require_v1(jsonb)','048b60e9637befdbbca317dba9db6d192bece6b298b1704bbcd306006b63c379',false,'v',true,'private'),\n ('_authority_role_move_binding_new_v1(jsonb,jsonb,integer)','d1bc74c3bd77e3082e27dbf89c536dd595bc98dde1efefa4b3f567d9c1130dbc',false,'i',true,'private'),"
 ],
 [
  "  ('_authority_role_move_binding_empty_require_v1(jsonb)','void',1,ARRAY['p_frozen']),",
  "  ('_authority_role_move_binding_empty_require_v1(jsonb)','void',1,ARRAY['p_frozen']),\n  ('_authority_role_move_binding_new_v1(jsonb,jsonb,integer)','jsonb',3,ARRAY['p_prepared','p_status','p_rows']),"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','6881336c2f6c0d0ab4c1fcfdea74376b7d3ccdebe2155efc49fb70fd7697abfc','3dfc1f4884a02964b029b6b3f242cae32d42ff2e84da42b70376310ac9cd0065',$changes$[
 [
  "5808081c4afa7ccdd6b831731532c1e645aa3c7162c1c8523da497ad68da425e",
  "707327736532ccc1a90362e3dcbccf69e4f0b86c4215fcf41cea66f972331e23"
 ]
]$changes$::jsonb),
  ('authority_metadata_service_account_access_label_ready_v1()','7163c0f805715bd7b808993a11276be90a9874cb0306d48232acb6cdd7fad5dc','f6bf60fab853f55d341b49c02c17d6cc5e3d5102cac46eff79834de1f8886c05',$changes$[
 [
  "5808081c4afa7ccdd6b831731532c1e645aa3c7162c1c8523da497ad68da425e",
  "707327736532ccc1a90362e3dcbccf69e4f0b86c4215fcf41cea66f972331e23"
 ],
 [
  "6881336c2f6c0d0ab4c1fcfdea74376b7d3ccdebe2155efc49fb70fd7697abfc",
  "3dfc1f4884a02964b029b6b3f242cae32d42ff2e84da42b70376310ac9cd0065"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move binding NEW predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move binding NEW splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move binding NEW body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move binding NEW function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move binding NEW function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move binding NEW custody differs after migration' USING ERRCODE='55000';END IF;
END;
$plan$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $plan$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('authority_metadata_service_account_access_label_ready_v1()','f6bf60fab853f55d341b49c02c17d6cc5e3d5102cac46eff79834de1f8886c05','7163c0f805715bd7b808993a11276be90a9874cb0306d48232acb6cdd7fad5dc',$changes$[
 [
  "3dfc1f4884a02964b029b6b3f242cae32d42ff2e84da42b70376310ac9cd0065",
  "6881336c2f6c0d0ab4c1fcfdea74376b7d3ccdebe2155efc49fb70fd7697abfc"
 ],
 [
  "707327736532ccc1a90362e3dcbccf69e4f0b86c4215fcf41cea66f972331e23",
  "5808081c4afa7ccdd6b831731532c1e645aa3c7162c1c8523da497ad68da425e"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','3dfc1f4884a02964b029b6b3f242cae32d42ff2e84da42b70376310ac9cd0065','6881336c2f6c0d0ab4c1fcfdea74376b7d3ccdebe2155efc49fb70fd7697abfc',$changes$[
 [
  "707327736532ccc1a90362e3dcbccf69e4f0b86c4215fcf41cea66f972331e23",
  "5808081c4afa7ccdd6b831731532c1e645aa3c7162c1c8523da497ad68da425e"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','707327736532ccc1a90362e3dcbccf69e4f0b86c4215fcf41cea66f972331e23','5808081c4afa7ccdd6b831731532c1e645aa3c7162c1c8523da497ad68da425e',$changes$[
 [
  "  ('_authority_role_move_binding_empty_require_v1(jsonb)','void',1,ARRAY['p_frozen']),\n  ('_authority_role_move_binding_new_v1(jsonb,jsonb,integer)','jsonb',3,ARRAY['p_prepared','p_status','p_rows']),",
  "  ('_authority_role_move_binding_empty_require_v1(jsonb)','void',1,ARRAY['p_frozen']),"
 ],
 [
  " ('_authority_role_move_binding_empty_require_v1(jsonb)','048b60e9637befdbbca317dba9db6d192bece6b298b1704bbcd306006b63c379',false,'v',true,'private'),\n ('_authority_role_move_binding_new_v1(jsonb,jsonb,integer)','d1bc74c3bd77e3082e27dbf89c536dd595bc98dde1efefa4b3f567d9c1130dbc',false,'i',true,'private'),",
  " ('_authority_role_move_binding_empty_require_v1(jsonb)','048b60e9637befdbbca317dba9db6d192bece6b298b1704bbcd306006b63c379',false,'v',true,'private'),"
 ],
 [
  "8cffc9e80a318ebb283446f57b16c6afa2deb4b06f6f075a91cf6fefcf81b273",
  "9e7772c3a4950497773c1e4d2dc7a0f747db4a03d08b8ac581747e50fcb43cb2"
 ]
]$changes$::jsonb),
  ('_authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)','8cffc9e80a318ebb283446f57b16c6afa2deb4b06f6f075a91cf6fefcf81b273','9e7772c3a4950497773c1e4d2dc7a0f747db4a03d08b8ac581747e50fcb43cb2',$changes$[
 [
  "'binding_status',carriers->'binding_status','binding_new',binding_new->'holders','rows',",
  "'binding_status',carriers->'binding_status','rows',"
 ],
 [
  "    binding_new:=kaname._authority_role_move_binding_new_v1(p_frozen,carriers->'binding_status',p_rows-used_rows);\n    used_rows:=used_rows+(binding_new->>'rows')::integer;\n    result:=kaname._authority_role_move_copy_requirements_require_v1",
  "    result:=kaname._authority_role_move_copy_requirements_require_v1"
 ],
 [
  "    carriers jsonb;\n    binding_new jsonb;",
  "    carriers jsonb;"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move binding NEW predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move binding NEW splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move binding NEW body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move binding NEW function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move binding NEW function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move binding NEW custody differs after migration' USING ERRCODE='55000';END IF;
END;
$plan$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_role_move_binding_new_v1(jsonb,jsonb,integer);
