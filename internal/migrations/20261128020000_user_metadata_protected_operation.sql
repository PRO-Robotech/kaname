-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- При записи и завершении операции сверяем физические версии 14000
-- и поколение доступа с фактами, утвержденными на финальном DecisionAt.
-- +goose StatementBegin
DO $protected$
DECLARE item record; pair jsonb; src text; fn regprocedure; grantee record;
BEGIN
    IF EXISTS(SELECT FROM (VALUES
        ('kaname._authority_metadata_user_protected_approve_v1(text,uuid,timestamptz,integer,integer,integer)','b608cd236554d4e0768fd3b1ec6d12e35f58282ca5210851b9f72254d008ee6b'),
        ('kaname._authority_metadata_user_freshness_assert_v1()','0ce926ffece76d7c1c7fffe31a540f65bad7110fe419e743336126c0d3e3d670')
    ) need(signature,digest) WHERE NOT EXISTS(SELECT FROM pg_catalog.pg_proc p
        WHERE p.oid=to_regprocedure(need.signature) AND p.proowner=current_user::regrole
            AND NOT p.prosecdef AND p.provolatile='v'
            AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=need.digest)) THEN
        RAISE EXCEPTION 'protected user approval or freshness prerequisite differs' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
        ('versions','','','jsonb','INVOKER',
         '00c66bd7f54f9d4914aa61b73997c6da7dd076b32be55bdf56eca24b2ea96259','ffe733e170d7eb30d7f5361851ecc30d8093365a35c1f429739914c9becb165f',
         $changes$[
 [
  "IS DISTINCT FROM 'ordinary'",
  "IS DISTINCT FROM 'access_labels'"
 ],
 [
  "IS DISTINCT FROM 'user_ordinary'",
  "IS DISTINCT FROM 'user_access_labels'"
 ],
 [
  "    SELECT jsonb_build_array(u.xmin::text,u.ctid::text) INTO ur",
  "    PERFORM kaname._authority_metadata_user_freshness_assert_v1();\n    SELECT jsonb_build_array(u.xmin::text,u.ctid::text) INTO ur"
 ],
 [
  "OR program->'nonce' IS DISTINCT FROM images->'nonce'",
  "OR program->'nonce' IS DISTINCT FROM images->'nonce'\n        OR program#>'{frozen,access_label_freshness_installed}' IS DISTINCT FROM program->'nonce'\n        OR (program#>>'{frozen,access_label_approved_at}')::timestamptz IS NULL\n        OR (program#>>'{frozen,access_label_approved_at}')::timestamptz IS DISTINCT FROM (program->>'decision_at')::timestamptz"
 ],
 [
  "'ordinary user selected effects differ'",
  "'protected user selected effects differ'"
 ],
 [
  "'ordinary user output or epoch differs'",
  "'protected user output or epoch differs'"
 ]
]$changes$::jsonb),
        ('write','text,uuid,timestamptz','p_op text,p_nonce uuid,p_decision timestamptz','jsonb','INVOKER',
         'ed62971ca486ab7aedc34a8075a9adacd70627218145816dfb5044b9ac066d80','9476b6eb07eb26c0347f4ee470ffec0295248e52e672fd6160fdb61eb17f2dfb',
         $changes$[
 [
  "IS DISTINCT FROM 'ordinary'",
  "IS DISTINCT FROM 'access_labels'"
 ],
 [
  "IS DISTINCT FROM 'user_ordinary'",
  "IS DISTINCT FROM 'user_access_labels'"
 ],
 [
  "IS DISTINCT FROM 'metadata.user.ordinary'",
  "IS DISTINCT FROM 'metadata.user.access_labels'"
 ],
 [
  "_authority_metadata_user_ordinary_versions_v1()",
  "_authority_metadata_user_protected_versions_v1()"
 ],
 [
  "OR p_decision IS NULL OR",
  "OR proof->>'consumer_finalized' IS DISTINCT FROM 'true'\n        OR p_decision IS NULL OR NOT isfinite(p_decision)\n        OR (cmd->>'access_label_approved_at')::timestamptz IS DISTINCT FROM p_decision OR"
 ],
 [
  "images->'changed_fields' IS DISTINCT FROM '[\"labels\"]'::jsonb\n        OR ((images->'new_row')-'labels') IS DISTINCT FROM ((images->'old_row')-'labels')",
  "images->'changed_fields' IS DISTINCT FROM (CASE\n            WHEN images#>'{old_row,labels}' IS DISTINCT FROM images#>'{new_row,labels}'\n                THEN '[\"labels\",\"access_labels\"]'::jsonb ELSE '[\"access_labels\"]'::jsonb END)\n        OR images#>'{old_row,access_labels}' IS NOT DISTINCT FROM images#>'{new_row,access_labels}'\n        OR ((images->'new_row')-ARRAY['labels','access_labels']) IS DISTINCT FROM ((images->'old_row')-ARRAY['labels','access_labels'])"
 ],
 [
  "OR p_nonce IS NULL",
  "OR cmd ? 'access_label_freshness_installed'\n        OR cmd->'access_label_root_physical' IS DISTINCT FROM physical\n        OR p_nonce IS NULL"
 ],
 [
  "    UPDATE ONLY kaname.users u SET labels=images#>'{new_row,labels}'\n    WHERE u.id=images->>'root_id' AND u.xmin::text=physical->>'xmin' AND u.ctid::text=physical->>'ctid'\n        AND to_jsonb(u)=images->'old_row'\n    RETURNING to_jsonb(u),jsonb_build_array(u.xmin::text,u.ctid::text) INTO actual,version;",
  "    IF images->'changed_fields'='[\"access_labels\"]'::jsonb THEN\n        UPDATE ONLY kaname.users u SET access_labels=images#>'{new_row,access_labels}'\n        WHERE u.id=images->>'root_id' AND u.xmin::text=physical->>'xmin' AND u.ctid::text=physical->>'ctid'\n            AND to_jsonb(u)=images->'old_row'\n        RETURNING to_jsonb(u),jsonb_build_array(u.xmin::text,u.ctid::text) INTO actual,version;\n    ELSE\n        UPDATE ONLY kaname.users u SET labels=images#>'{new_row,labels}',access_labels=images#>'{new_row,access_labels}'\n        WHERE u.id=images->>'root_id' AND u.xmin::text=physical->>'xmin' AND u.ctid::text=physical->>'ctid'\n            AND to_jsonb(u)=images->'old_row'\n        RETURNING to_jsonb(u),jsonb_build_array(u.xmin::text,u.ctid::text) INTO actual,version;\n    END IF;"
 ],
 [
  "    versions jsonb;",
  "    versions jsonb;\n    installed jsonb;"
 ],
 [
  "    audit:=jsonb_populate_record",
  "    installed:=cmd||jsonb_build_object('phase','writing','access_label_freshness_installed',p_nonce);\n    IF NOT EXISTS(SELECT FROM pg_temp.kaname_authority_sequence_program s\n        WHERE s.singleton AND s.nonce=p_nonce AND s.frozen=installed) THEN\n        RAISE EXCEPTION 'protected user freshness installation differs from approved write' USING ERRCODE='42501';\n    END IF;\n    audit:=jsonb_populate_record"
 ],
 [
  "SET frozen=cmd||jsonb_build_object('phase','written','versions',versions)",
  "SET frozen=installed||jsonb_build_object('phase','written','versions',versions)"
 ],
 [
  "s.frozen=cmd||jsonb_build_object('phase','writing') AND versions->'user'=version",
  "s.frozen=installed AND versions->'user'=version"
 ],
 [
  "'ordinary user mutation has no matching final decision'",
  "'protected user mutation has no matching final decision'"
 ],
 [
  "'ordinary user mutation repeated'",
  "'protected user mutation repeated'"
 ],
 [
  "'ordinary user physical update changed'",
  "'protected user physical update changed'"
 ],
 [
  "'ordinary user receipt changed'",
  "'protected user receipt changed'"
 ]
]$changes$::jsonb),
        ('complete','text,uuid,timestamptz,bytea','p_op text,p_nonce uuid,p_decision timestamptz,p_response bytea','kaname.operations','INVOKER',
         '675bcd6a9a8db783d5bfcc8ee4a8f8662e3d7c7099f6576cd92b15fc00c4067b','ae2f510abbea172a8156d2ecdfe4228aad2b5cdfd3c8aae907cc3ff419b4abf9',
         $changes$[
 [
  "IS DISTINCT FROM 'ordinary'",
  "IS DISTINCT FROM 'access_labels'"
 ],
 [
  "IS DISTINCT FROM 'user_ordinary'",
  "IS DISTINCT FROM 'user_access_labels'"
 ],
 [
  "IS DISTINCT FROM 'metadata.user.ordinary'",
  "IS DISTINCT FROM 'metadata.user.access_labels'"
 ],
 [
  "_authority_metadata_user_ordinary_versions_v1()",
  "_authority_metadata_user_protected_versions_v1()"
 ],
 [
  "OR p_decision IS NULL OR",
  "OR proof->>'consumer_finalized' IS DISTINCT FROM 'true'\n        OR p_decision IS NULL OR NOT isfinite(p_decision)\n        OR (cmd->>'access_label_approved_at')::timestamptz IS DISTINCT FROM p_decision OR"
 ],
 [
  "'ordinary user has no final decision for this operation'",
  "'protected user has no final decision for this operation'"
 ],
 [
  "'ordinary user already consumed'",
  "'protected user already consumed'"
 ],
 [
  "'ordinary user final operation changed'",
  "'protected user final operation changed'"
 ],
 [
  "'ordinary user terminal receipt absent'",
  "'protected user terminal receipt absent'"
 ]
]$changes$::jsonb),
        ('commit','','','trigger','DEFINER',
         'abff163a2ac3a7e5148ec44181ca115f21be07fff6a1cfe66732113b631ead4c','557afff6f9c9b3d1df865fe6622436e38e2fec58241ad72b855c3fa363b2242c',
         $changes$[
 [
  "IS DISTINCT FROM 'ordinary'",
  "IS DISTINCT FROM 'access_labels'"
 ],
 [
  "IS DISTINCT FROM 'user_ordinary'",
  "IS DISTINCT FROM 'user_access_labels'"
 ],
 [
  "IS DISTINCT FROM 'metadata.user.ordinary'",
  "IS DISTINCT FROM 'metadata.user.access_labels'"
 ],
 [
  "_authority_metadata_user_ordinary_versions_v1()",
  "_authority_metadata_user_protected_versions_v1()"
 ],
 [
  "images->'changed_fields' IS DISTINCT FROM '[\"labels\"]'::jsonb OR ((images->'old_row')-'labels') IS DISTINCT FROM ((images->'new_row')-'labels')",
  "images->'changed_fields' IS DISTINCT FROM (CASE\n            WHEN images#>'{old_row,labels}' IS DISTINCT FROM images#>'{new_row,labels}'\n                THEN '[\"labels\",\"access_labels\"]'::jsonb ELSE '[\"access_labels\"]'::jsonb END)\n        OR images#>'{old_row,access_labels}' IS NOT DISTINCT FROM images#>'{new_row,access_labels}'\n        OR ((images->'new_row')-ARRAY['labels','access_labels']) IS DISTINCT FROM ((images->'old_row')-ARRAY['labels','access_labels'])"
 ],
 [
  "IF images IS DISTINCT FROM NEW.prepared->'user_images'",
  "IF OLD.prepared ? 'user_protected_reserved'\n        OR NEW.prepared->'user_protected_reserved' IS DISTINCT FROM images->'nonce'\n        OR images IS DISTINCT FROM NEW.prepared->'user_images'"
 ],
 [
  "OR program->'nonce' IS DISTINCT FROM images->'nonce'",
  "OR (cmd->>'decision')::timestamptz IS NULL\n        OR (cmd->>'access_label_approved_at')::timestamptz IS DISTINCT FROM (cmd->>'decision')::timestamptz\n        OR cmd->'access_label_freshness_installed' IS DISTINCT FROM images->'nonce'\n        OR program->'nonce' IS DISTINCT FROM images->'nonce'"
 ],
 [
  "'ordinary user commit origin differs'",
  "'protected user commit origin differs'"
 ],
 [
  "'ordinary user operation was not completed by this decision'",
  "'protected user operation was not completed by this decision'"
 ],
 [
  "'ordinary user terminal operation changed'",
  "'protected user terminal operation changed'"
 ],
 [
  "'ordinary user retained identity changed'",
  "'protected user retained identity changed'"
 ]
]$changes$::jsonb)
    ) s(name,signature,args,ret,security,before_digest,after_digest,changes) LOOP
        SELECT p.prosrc INTO STRICT src FROM pg_catalog.pg_proc p
        WHERE p.oid=to_regprocedure('kaname._authority_metadata_user_ordinary_'||item.name||'_v1('||item.signature||')')
            AND p.proowner=current_user::regrole AND p.prosecdef=(item.security='DEFINER') AND p.provolatile='v';
        IF encode(sha256(convert_to(src,'UTF8')),'hex') IS DISTINCT FROM item.before_digest THEN
            RAISE EXCEPTION 'protected user prerequisite differs: %',item.name USING ERRCODE='55000';
        END IF;
        FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
            IF length(src)-length(replace(src,pair->>0,''))<>length(pair->>0) THEN
                RAISE EXCEPTION 'protected user edit is not unique: %',item.name USING ERRCODE='55000';
            END IF;
            src:=replace(src,pair->>0,pair->>1);
        END LOOP;
        IF encode(sha256(convert_to(src,'UTF8')),'hex') IS DISTINCT FROM item.after_digest THEN
            RAISE EXCEPTION 'protected user result differs: %',item.name USING ERRCODE='55000';
        END IF;
        EXECUTE format('CREATE FUNCTION kaname.%I(%s) RETURNS %s LANGUAGE plpgsql VOLATILE SECURITY %s
            SET search_path=pg_catalog,pg_temp AS %L','_authority_metadata_user_protected_'||item.name||'_v1',
            item.args,item.ret,item.security,src);
        fn:=('kaname._authority_metadata_user_protected_'||item.name||'_v1('||item.signature||')')::regprocedure;
        FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
                CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE quote_ident(grantee.rolname) END);
        END LOOP;
    END LOOP;
END;
$protected$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $guard$
DECLARE src text; fn regprocedure:='kaname._authority_metadata_user_noop_transition_v1(text,jsonb,jsonb)'::regprocedure;
BEGIN
    SELECT p.prosrc INTO STRICT src FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole
        AND NOT p.prosecdef AND p.provolatile='v';
    IF encode(sha256(convert_to(src,'UTF8')),'hex') IS DISTINCT FROM '1c096fa8d245f942634532aeb8244eca49d62e8c076b899ca8bff0b6c09ebe7e' THEN
        RAISE EXCEPTION 'protected user terminal guard prerequisite differs' USING ERRCODE='55000';
    END IF;
    src:=replace(src,$old$('user_noop','user_ordinary')$old$,$new$('user_noop','user_ordinary','user_access_labels')$new$);
    IF encode(sha256(convert_to(src,'UTF8')),'hex') IS DISTINCT FROM 'aaf3a7b4157c1106c1b9820dd27ed3c44061803bcd869cdcea33aa8f79f39ddc' THEN
        RAISE EXCEPTION 'protected user terminal guard differs' USING ERRCODE='55000';
    END IF;
    EXECUTE format('CREATE OR REPLACE FUNCTION kaname._authority_metadata_user_noop_transition_v1(p_when text,p_old jsonb,p_new jsonb)
        RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS %L',src);
END;
$guard$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
LOCK TABLE ONLY kaname.operations IN ACCESS EXCLUSIVE MODE;

-- +goose StatementBegin
DO $guard$
DECLARE src text; fn regprocedure:='kaname._authority_metadata_user_noop_transition_v1(text,jsonb,jsonb)'::regprocedure;
BEGIN
    SELECT p.prosrc INTO STRICT src FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole
        AND NOT p.prosecdef AND p.provolatile='v';
    IF encode(sha256(convert_to(src,'UTF8')),'hex') IS DISTINCT FROM 'aaf3a7b4157c1106c1b9820dd27ed3c44061803bcd869cdcea33aa8f79f39ddc' THEN
        RAISE EXCEPTION 'protected user terminal guard prerequisite differs' USING ERRCODE='55000';
    END IF;
    src:=replace(src,$old$('user_noop','user_ordinary','user_access_labels')$old$,$new$('user_noop','user_ordinary')$new$);
    IF encode(sha256(convert_to(src,'UTF8')),'hex') IS DISTINCT FROM '1c096fa8d245f942634532aeb8244eca49d62e8c076b899ca8bff0b6c09ebe7e' THEN
        RAISE EXCEPTION 'protected user terminal guard differs' USING ERRCODE='55000';
    END IF;
    EXECUTE format('CREATE OR REPLACE FUNCTION kaname._authority_metadata_user_noop_transition_v1(p_when text,p_old jsonb,p_new jsonb)
        RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS %L',src);
END;
$guard$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_metadata_user_protected_commit_v1();
DROP FUNCTION kaname._authority_metadata_user_protected_complete_v1(text,uuid,timestamptz,bytea);
DROP FUNCTION kaname._authority_metadata_user_protected_write_v1(text,uuid,timestamptz);
DROP FUNCTION kaname._authority_metadata_user_protected_versions_v1();
