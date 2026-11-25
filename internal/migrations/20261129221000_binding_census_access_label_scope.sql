-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Селектор по меткам доступа требует полного прохода, как и прочие
-- неякорные селекторы. Форму поля проверяет fingerprint до расчёта census.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $storage$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_binding_census_projection_v3(jsonb,jsonb,integer,jsonb)','36963e0529cbc6e5264d76b1d8aa88eea1f19839bfec61684821fac060f59478','7b70bf0d54064f23d175e73416750e1aafc719127c1fa73cee0d9bc70b541e88',$edits$[["   OR coalesce(nullif(rule->'match_labels','null'::jsonb),'{}'::jsonb)<>'{}'::jsonb)","   OR coalesce(nullif(rule->'match_labels','null'::jsonb),'{}'::jsonb)<>'{}'::jsonb\n   OR rule ? 'match_access_labels')"]]$edits$::jsonb),
        ('_authority_crud_storage_v3()','d22a84673647caece6ca57630ddae79bf7a9b73740996ed5885d8c88ce92b7ac','4053b0faf5a68785d704fc785b9f87d70d3c82694a1ef1e9cd9febd672657b20',$edits$[["36963e0529cbc6e5264d76b1d8aa88eea1f19839bfec61684821fac060f59478","7b70bf0d54064f23d175e73416750e1aafc719127c1fa73cee0d9bc70b541e88"]]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','ecb3b446e31adeb43418742d3a012ff321fc42ce39ae3b9cfc0efbca65479e7b','d87f4a9ef29da240ab771ec5394d7b18a3fcb9ae570d7f41891f32b3a1c664e3',$edits$[["d22a84673647caece6ca57630ddae79bf7a9b73740996ed5885d8c88ce92b7ac","4053b0faf5a68785d704fc785b9f87d70d3c82694a1ef1e9cd9febd672657b20"]]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','3dcd78286c42a56371a2111c13e3d78c618d5f092d57dfe2ed81449bdea05afa','f3a35ec27e00cc609e326bdb84a9b8b798d54d29d0b5bca626acb3e8e6e81620',$edits$[["d22a84673647caece6ca57630ddae79bf7a9b73740996ed5885d8c88ce92b7ac","4053b0faf5a68785d704fc785b9f87d70d3c82694a1ef1e9cd9febd672657b20"],["ecb3b446e31adeb43418742d3a012ff321fc42ce39ae3b9cfc0efbca65479e7b","d87f4a9ef29da240ab771ec5394d7b18a3fcb9ae570d7f41891f32b3a1c664e3"]]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','472060c1ff35f223c9b960cbefd4a35793af442ec2551582dd8617d9923127b4','312e9c88f989f3d1cd11d9ceb6e088b93765a714d060b0587a10bb0c2ee3e3f7',$edits$[["ecb3b446e31adeb43418742d3a012ff321fc42ce39ae3b9cfc0efbca65479e7b","d87f4a9ef29da240ab771ec5394d7b18a3fcb9ae570d7f41891f32b3a1c664e3"]]$edits$::jsonb),
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','d3f1433033dc3c43fd8aa9bb3bf965cc6b888f7db2337fee156a580367d87405','325bb03f89deb5e8bd8cf3a8c259c941ec53668e039b0013a1f77e8e85368e70',$edits$[["472060c1ff35f223c9b960cbefd4a35793af442ec2551582dd8617d9923127b4","312e9c88f989f3d1cd11d9ceb6e088b93765a714d060b0587a10bb0c2ee3e3f7"]]$edits$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'access-label binding census predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'access-label binding census replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'access-label binding census body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'access-label binding census installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'access-label binding census storage graph differs' USING ERRCODE='55000';
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
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','325bb03f89deb5e8bd8cf3a8c259c941ec53668e039b0013a1f77e8e85368e70','d3f1433033dc3c43fd8aa9bb3bf965cc6b888f7db2337fee156a580367d87405',$edits$[["312e9c88f989f3d1cd11d9ceb6e088b93765a714d060b0587a10bb0c2ee3e3f7","472060c1ff35f223c9b960cbefd4a35793af442ec2551582dd8617d9923127b4"]]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','312e9c88f989f3d1cd11d9ceb6e088b93765a714d060b0587a10bb0c2ee3e3f7','472060c1ff35f223c9b960cbefd4a35793af442ec2551582dd8617d9923127b4',$edits$[["d87f4a9ef29da240ab771ec5394d7b18a3fcb9ae570d7f41891f32b3a1c664e3","ecb3b446e31adeb43418742d3a012ff321fc42ce39ae3b9cfc0efbca65479e7b"]]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','f3a35ec27e00cc609e326bdb84a9b8b798d54d29d0b5bca626acb3e8e6e81620','3dcd78286c42a56371a2111c13e3d78c618d5f092d57dfe2ed81449bdea05afa',$edits$[["d87f4a9ef29da240ab771ec5394d7b18a3fcb9ae570d7f41891f32b3a1c664e3","ecb3b446e31adeb43418742d3a012ff321fc42ce39ae3b9cfc0efbca65479e7b"],["4053b0faf5a68785d704fc785b9f87d70d3c82694a1ef1e9cd9febd672657b20","d22a84673647caece6ca57630ddae79bf7a9b73740996ed5885d8c88ce92b7ac"]]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','d87f4a9ef29da240ab771ec5394d7b18a3fcb9ae570d7f41891f32b3a1c664e3','ecb3b446e31adeb43418742d3a012ff321fc42ce39ae3b9cfc0efbca65479e7b',$edits$[["4053b0faf5a68785d704fc785b9f87d70d3c82694a1ef1e9cd9febd672657b20","d22a84673647caece6ca57630ddae79bf7a9b73740996ed5885d8c88ce92b7ac"]]$edits$::jsonb),
        ('_authority_crud_storage_v3()','4053b0faf5a68785d704fc785b9f87d70d3c82694a1ef1e9cd9febd672657b20','d22a84673647caece6ca57630ddae79bf7a9b73740996ed5885d8c88ce92b7ac',$edits$[["7b70bf0d54064f23d175e73416750e1aafc719127c1fa73cee0d9bc70b541e88","36963e0529cbc6e5264d76b1d8aa88eea1f19839bfec61684821fac060f59478"]]$edits$::jsonb),
        ('_authority_binding_census_projection_v3(jsonb,jsonb,integer,jsonb)','7b70bf0d54064f23d175e73416750e1aafc719127c1fa73cee0d9bc70b541e88','36963e0529cbc6e5264d76b1d8aa88eea1f19839bfec61684821fac060f59478',$edits$[["   OR coalesce(nullif(rule->'match_labels','null'::jsonb),'{}'::jsonb)<>'{}'::jsonb\n   OR rule ? 'match_access_labels')","   OR coalesce(nullif(rule->'match_labels','null'::jsonb),'{}'::jsonb)<>'{}'::jsonb)"]]$edits$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'access-label binding census predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'access-label binding census replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'access-label binding census body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'access-label binding census installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'access-label binding census storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage$;
-- +goose StatementEnd
