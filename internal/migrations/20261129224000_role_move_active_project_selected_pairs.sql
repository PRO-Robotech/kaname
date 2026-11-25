-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Оба предиката проверяются на удержанном полном образе одного проекта.
-- Другие пары не входят в правило и не требуют изменения объекта.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $storage$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_role_move_active_project_witness_v1(jsonb,integer,integer)','6cd17d6bdd7e630c45a642ec8b0373df820ae30361d007eb35779cb861a01826','4ce6308062ed252ec8873a932f5c741201b263ca6c425594c606f33264a33de1',$edits$[
 [
  "project_row->'labels' IS DISTINCT FROM project_row->'access_labels'",
  "(project_row->'access_labels' @> (new_rule->'match_access_labels')) IS DISTINCT FROM true"
 ]
]$edits$::jsonb),
        ('_authority_role_move_active_fga_slot_v1(jsonb,integer,integer,integer)','f46d147bd9a7101f1dc2a3af0875a8f94dfadc0125b3848431456a751850c60a','246bf42e5f97da9d343d6b9862534b55f0782b08e741141a94829b3d6b1cc172',$edits$[
 [
  "pr->'labels' IS DISTINCT FROM pr->'access_labels'",
  "(pr->'labels' @> (old_rule->'match_labels')) IS DISTINCT FROM true"
 ]
]$edits$::jsonb),
        ('_authority_crud_storage_v3()','4053b0faf5a68785d704fc785b9f87d70d3c82694a1ef1e9cd9febd672657b20','b24879ddb0e3b8f134f1a56333732fbfdd2be9958e1ebdc35089fcdefaf25495',$edits$[
 [
  "6cd17d6bdd7e630c45a642ec8b0373df820ae30361d007eb35779cb861a01826",
  "4ce6308062ed252ec8873a932f5c741201b263ca6c425594c606f33264a33de1"
 ],
 [
  "f46d147bd9a7101f1dc2a3af0875a8f94dfadc0125b3848431456a751850c60a",
  "246bf42e5f97da9d343d6b9862534b55f0782b08e741141a94829b3d6b1cc172"
 ]
]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','d87f4a9ef29da240ab771ec5394d7b18a3fcb9ae570d7f41891f32b3a1c664e3','822c79b98bc6f0045ded4c5f028a2a3e96b46a108d7d5fe6df839cf170a1c692',$edits$[
 [
  "4053b0faf5a68785d704fc785b9f87d70d3c82694a1ef1e9cd9febd672657b20",
  "b24879ddb0e3b8f134f1a56333732fbfdd2be9958e1ebdc35089fcdefaf25495"
 ]
]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','f3a35ec27e00cc609e326bdb84a9b8b798d54d29d0b5bca626acb3e8e6e81620','930c422666f0da334bc3bf03190f43185a4cbf7fd9d57db5f4eb2b29bee99d37',$edits$[
 [
  "4053b0faf5a68785d704fc785b9f87d70d3c82694a1ef1e9cd9febd672657b20",
  "b24879ddb0e3b8f134f1a56333732fbfdd2be9958e1ebdc35089fcdefaf25495"
 ],
 [
  "d87f4a9ef29da240ab771ec5394d7b18a3fcb9ae570d7f41891f32b3a1c664e3",
  "822c79b98bc6f0045ded4c5f028a2a3e96b46a108d7d5fe6df839cf170a1c692"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','312e9c88f989f3d1cd11d9ceb6e088b93765a714d060b0587a10bb0c2ee3e3f7','56e14e491def1c66df6b279eb0b5a3948221dd990a82ccafdf7cc322ac50e8d2',$edits$[
 [
  "d87f4a9ef29da240ab771ec5394d7b18a3fcb9ae570d7f41891f32b3a1c664e3",
  "822c79b98bc6f0045ded4c5f028a2a3e96b46a108d7d5fe6df839cf170a1c692"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','325bb03f89deb5e8bd8cf3a8c259c941ec53668e039b0013a1f77e8e85368e70','32b0e594751f3a6a5e3b9929434be3062dc2ef89dcfe95bc6434d9d81ee2f1db',$edits$[
 [
  "312e9c88f989f3d1cd11d9ceb6e088b93765a714d060b0587a10bb0c2ee3e3f7",
  "56e14e491def1c66df6b279eb0b5a3948221dd990a82ccafdf7cc322ac50e8d2"
 ]
]$edits$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'active project selected pairs predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'active project selected pairs replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'active project selected pairs body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'active project selected pairs installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'active project selected pairs storage graph differs' USING ERRCODE='55000';
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
        ('_authority_role_move_active_project_witness_v1(jsonb,integer,integer)','4ce6308062ed252ec8873a932f5c741201b263ca6c425594c606f33264a33de1','6cd17d6bdd7e630c45a642ec8b0373df820ae30361d007eb35779cb861a01826',$edits$[
 [
  "(project_row->'access_labels' @> (new_rule->'match_access_labels')) IS DISTINCT FROM true",
  "project_row->'labels' IS DISTINCT FROM project_row->'access_labels'"
 ]
]$edits$::jsonb),
        ('_authority_role_move_active_fga_slot_v1(jsonb,integer,integer,integer)','246bf42e5f97da9d343d6b9862534b55f0782b08e741141a94829b3d6b1cc172','f46d147bd9a7101f1dc2a3af0875a8f94dfadc0125b3848431456a751850c60a',$edits$[
 [
  "(pr->'labels' @> (old_rule->'match_labels')) IS DISTINCT FROM true",
  "pr->'labels' IS DISTINCT FROM pr->'access_labels'"
 ]
]$edits$::jsonb),
        ('_authority_crud_storage_v3()','b24879ddb0e3b8f134f1a56333732fbfdd2be9958e1ebdc35089fcdefaf25495','4053b0faf5a68785d704fc785b9f87d70d3c82694a1ef1e9cd9febd672657b20',$edits$[
 [
  "246bf42e5f97da9d343d6b9862534b55f0782b08e741141a94829b3d6b1cc172",
  "f46d147bd9a7101f1dc2a3af0875a8f94dfadc0125b3848431456a751850c60a"
 ],
 [
  "4ce6308062ed252ec8873a932f5c741201b263ca6c425594c606f33264a33de1",
  "6cd17d6bdd7e630c45a642ec8b0373df820ae30361d007eb35779cb861a01826"
 ]
]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','822c79b98bc6f0045ded4c5f028a2a3e96b46a108d7d5fe6df839cf170a1c692','d87f4a9ef29da240ab771ec5394d7b18a3fcb9ae570d7f41891f32b3a1c664e3',$edits$[
 [
  "b24879ddb0e3b8f134f1a56333732fbfdd2be9958e1ebdc35089fcdefaf25495",
  "4053b0faf5a68785d704fc785b9f87d70d3c82694a1ef1e9cd9febd672657b20"
 ]
]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','930c422666f0da334bc3bf03190f43185a4cbf7fd9d57db5f4eb2b29bee99d37','f3a35ec27e00cc609e326bdb84a9b8b798d54d29d0b5bca626acb3e8e6e81620',$edits$[
 [
  "822c79b98bc6f0045ded4c5f028a2a3e96b46a108d7d5fe6df839cf170a1c692",
  "d87f4a9ef29da240ab771ec5394d7b18a3fcb9ae570d7f41891f32b3a1c664e3"
 ],
 [
  "b24879ddb0e3b8f134f1a56333732fbfdd2be9958e1ebdc35089fcdefaf25495",
  "4053b0faf5a68785d704fc785b9f87d70d3c82694a1ef1e9cd9febd672657b20"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','56e14e491def1c66df6b279eb0b5a3948221dd990a82ccafdf7cc322ac50e8d2','312e9c88f989f3d1cd11d9ceb6e088b93765a714d060b0587a10bb0c2ee3e3f7',$edits$[
 [
  "822c79b98bc6f0045ded4c5f028a2a3e96b46a108d7d5fe6df839cf170a1c692",
  "d87f4a9ef29da240ab771ec5394d7b18a3fcb9ae570d7f41891f32b3a1c664e3"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','32b0e594751f3a6a5e3b9929434be3062dc2ef89dcfe95bc6434d9d81ee2f1db','325bb03f89deb5e8bd8cf3a8c259c941ec53668e039b0013a1f77e8e85368e70',$edits$[
 [
  "56e14e491def1c66df6b279eb0b5a3948221dd990a82ccafdf7cc322ac50e8d2",
  "312e9c88f989f3d1cd11d9ceb6e088b93765a714d060b0587a10bb0c2ee3e3f7"
 ]
]$edits$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'active project selected pairs predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'active project selected pairs replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'active project selected pairs body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'active project selected pairs installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'active project selected pairs storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage$;
-- +goose StatementEnd
