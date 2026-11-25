-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $storage$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_binding_census_projection_v3(jsonb,jsonb,integer,jsonb)','849a2b29bd3a74847c0a173befc95374d46959691f519eba0da2d64d59cf2efe','f32a39b6798a7cc24e3741b5f4754053ce39806b4df88679bf6f5a2e3f8beb4e',$edits$[
 [
  "jsonb_typeof(c.value->'match_access_labels')='object'",
  "(jsonb_typeof(r.rule->'match_access_labels')='object' OR jsonb_typeof(c.value->'match_access_labels')='object')"
 ]
]$edits$::jsonb),
        ('_authority_crud_storage_v3()','3e26f0d8f46bfe0bc4dc3e8b20a7a9598c10824b1ff57599fc21afa250e97cd5','a31f1bfc21ee5ee2da22e79e3a22cc2f03b9ca3ed676a6d3bf8fc7ccc1b39b85',$edits$[
 [
  "849a2b29bd3a74847c0a173befc95374d46959691f519eba0da2d64d59cf2efe",
  "f32a39b6798a7cc24e3741b5f4754053ce39806b4df88679bf6f5a2e3f8beb4e"
 ]
]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','ea96a7b7a34af312cead751c9ee8a54de914b4004ebbdd14676082abd795ed16','18d347c292b6ad2a7095cea798cce0fbab5c26cfd40d10c0edf1d83c056f5b62',$edits$[
 [
  "3e26f0d8f46bfe0bc4dc3e8b20a7a9598c10824b1ff57599fc21afa250e97cd5",
  "a31f1bfc21ee5ee2da22e79e3a22cc2f03b9ca3ed676a6d3bf8fc7ccc1b39b85"
 ]
]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','0c601a5c9b6a2370bb482d23a46ab2c973a88b1313d93598a781b8e78b502dac','e0e32fe416eb94c877244b27eb718f84cc92ad0aba4e1407f9a5840359281b19',$edits$[
 [
  "3e26f0d8f46bfe0bc4dc3e8b20a7a9598c10824b1ff57599fc21afa250e97cd5",
  "a31f1bfc21ee5ee2da22e79e3a22cc2f03b9ca3ed676a6d3bf8fc7ccc1b39b85"
 ],
 [
  "ea96a7b7a34af312cead751c9ee8a54de914b4004ebbdd14676082abd795ed16",
  "18d347c292b6ad2a7095cea798cce0fbab5c26cfd40d10c0edf1d83c056f5b62"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','d3e61da2c5c7e258e019506cea5fdb884e265922fd4149ac8ce0259928dc9f8c','54f31a9d2f6ce4e1ee963d0d1e9a42fd82c162b4d433f7b5a5b13359e257153e',$edits$[
 [
  "ea96a7b7a34af312cead751c9ee8a54de914b4004ebbdd14676082abd795ed16",
  "18d347c292b6ad2a7095cea798cce0fbab5c26cfd40d10c0edf1d83c056f5b62"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','98dd9db5faa75bd513330519d03e4a4666f799847cd44349929b8912bb3e5273','f57ab3f10762ef5dc47b2315301215e4f180fbf6cdb51e1292b5a5c09d27df9e',$edits$[
 [
  "d3e61da2c5c7e258e019506cea5fdb884e265922fd4149ac8ce0259928dc9f8c",
  "54f31a9d2f6ce4e1ee963d0d1e9a42fd82c162b4d433f7b5a5b13359e257153e"
 ]
]$edits$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'staged native project container protection predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'staged native project container protection replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'staged native project container protection body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'staged native project container protection installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'staged native project container protection storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $storage$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_binding_census_projection_v3(jsonb,jsonb,integer,jsonb)','f32a39b6798a7cc24e3741b5f4754053ce39806b4df88679bf6f5a2e3f8beb4e','849a2b29bd3a74847c0a173befc95374d46959691f519eba0da2d64d59cf2efe',$edits$[
 [
  "(jsonb_typeof(r.rule->'match_access_labels')='object' OR jsonb_typeof(c.value->'match_access_labels')='object')",
  "jsonb_typeof(c.value->'match_access_labels')='object'"
 ]
]$edits$::jsonb),
        ('_authority_crud_storage_v3()','a31f1bfc21ee5ee2da22e79e3a22cc2f03b9ca3ed676a6d3bf8fc7ccc1b39b85','3e26f0d8f46bfe0bc4dc3e8b20a7a9598c10824b1ff57599fc21afa250e97cd5',$edits$[
 [
  "f32a39b6798a7cc24e3741b5f4754053ce39806b4df88679bf6f5a2e3f8beb4e",
  "849a2b29bd3a74847c0a173befc95374d46959691f519eba0da2d64d59cf2efe"
 ]
]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','18d347c292b6ad2a7095cea798cce0fbab5c26cfd40d10c0edf1d83c056f5b62','ea96a7b7a34af312cead751c9ee8a54de914b4004ebbdd14676082abd795ed16',$edits$[
 [
  "a31f1bfc21ee5ee2da22e79e3a22cc2f03b9ca3ed676a6d3bf8fc7ccc1b39b85",
  "3e26f0d8f46bfe0bc4dc3e8b20a7a9598c10824b1ff57599fc21afa250e97cd5"
 ]
]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','e0e32fe416eb94c877244b27eb718f84cc92ad0aba4e1407f9a5840359281b19','0c601a5c9b6a2370bb482d23a46ab2c973a88b1313d93598a781b8e78b502dac',$edits$[
 [
  "18d347c292b6ad2a7095cea798cce0fbab5c26cfd40d10c0edf1d83c056f5b62",
  "ea96a7b7a34af312cead751c9ee8a54de914b4004ebbdd14676082abd795ed16"
 ],
 [
  "a31f1bfc21ee5ee2da22e79e3a22cc2f03b9ca3ed676a6d3bf8fc7ccc1b39b85",
  "3e26f0d8f46bfe0bc4dc3e8b20a7a9598c10824b1ff57599fc21afa250e97cd5"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','54f31a9d2f6ce4e1ee963d0d1e9a42fd82c162b4d433f7b5a5b13359e257153e','d3e61da2c5c7e258e019506cea5fdb884e265922fd4149ac8ce0259928dc9f8c',$edits$[
 [
  "18d347c292b6ad2a7095cea798cce0fbab5c26cfd40d10c0edf1d83c056f5b62",
  "ea96a7b7a34af312cead751c9ee8a54de914b4004ebbdd14676082abd795ed16"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','f57ab3f10762ef5dc47b2315301215e4f180fbf6cdb51e1292b5a5c09d27df9e','98dd9db5faa75bd513330519d03e4a4666f799847cd44349929b8912bb3e5273',$edits$[
 [
  "54f31a9d2f6ce4e1ee963d0d1e9a42fd82c162b4d433f7b5a5b13359e257153e",
  "d3e61da2c5c7e258e019506cea5fdb884e265922fd4149ac8ce0259928dc9f8c"
 ]
]$edits$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'staged native project container protection predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'staged native project container protection replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'staged native project container protection body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'staged native project container protection installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'staged native project container protection storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage$;
-- +goose StatementEnd
