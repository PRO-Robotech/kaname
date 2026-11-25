-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- В обычном CREATE фактическая строка получает '{}' от DEFAULT. Тот же
-- результат нужен в подготовленном образе, чтобы точная сверка проходила.
-- Повторная регистрация ресурса сохраняет защищённые значения прежней строки.

-- +goose Up
-- +goose StatementBegin
DO $access_label_create_images$
DECLARE
    item record;
    replacement jsonb;
    fn regprocedure;
    old_body text;
    new_body text;
    definition text;
    needle text;
BEGIN
    PERFORM kaname.authority_protocol_drain();
    IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
        RAISE EXCEPTION 'несогласованное состояние перед обновлением образов доступа' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
        (
            '_authority_crud_domain_images_v3(jsonb,jsonb,jsonb,timestamptz)',
            '2e4cf1562674897a696483469505925ba5862b6fe0422f663b330eb96f237b9e',
            '092aea9c77c443b16de6c595ee2aeca2d22984fdbaf54831faad5b38659ce11d',
            $patch$[
            ["'labels',coalesce(nullif(request->'Labels','null'::jsonb),'{}'::jsonb),'created_at',p_at);", "'labels',coalesce(nullif(request->'Labels','null'::jsonb),'{}'::jsonb),'access_labels','{}'::jsonb,'created_at',p_at);"],
            ["'scope',2,'deletion_protection',true,'labels','{}'::jsonb,'target',jsonb_build_object('allInScope',true),", "'scope',2,'deletion_protection',true,'labels','{}'::jsonb,'access_labels','{}'::jsonb,'target',jsonb_build_object('allInScope',true),"]
            ]$patch$::jsonb
        ),
        (
            'authority_binding_sequence_prepare_v3(text,jsonb)',
            'bc276ed48b9a8e9d4eeb6cb472bfbda1a1a400dd8b34992f391f9423143272fc',
            'a0290994e32a6eb0a8c753b3be6bff865afcb3a40d4a6f9dafcef0aa1c7beb3c',
            $patch$[
            ["'revocation_reason',NULL,'grant_capability_version',0)));", "'revocation_reason',NULL,'grant_capability_version',0,'access_labels','{}'::jsonb)));"]
            ]$patch$::jsonb
        ),
        (
            'authority_role_sequence_prepare_v3(jsonb,integer,integer)',
            '5d47e24c50baaa1619a6cfb2198255c248fec06d535e13febacf7078c6aeae64',
            '5b08a8fb6bc43f571427993195d90b880c52fb2cdce91e29ead346579152eeb9',
            $patch$[
            ["'retired_at',NULL,'retired_reason',NULL,'retired_by',NULL,'created_at',root_stamp,'updated_at',root_stamp)));", "'retired_at',NULL,'retired_reason',NULL,'retired_by',NULL,'access_labels','{}'::jsonb,'created_at',root_stamp,'updated_at',root_stamp)));"]
            ]$patch$::jsonb
        ),
        (
            '_authority_resource_registration_mirror_images_v2(jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz)',
            '909c304c45925ad0cee62e8ddc462b381778fffd89739e36b99195bea4f3b6f7',
            '4fd40a4e10d3a8a31dfd02e02840da2a3ff31b45f2416c147c4f3e38d79f1b21',
            $patch$[
            ["old_row ?& ARRAY['parent_project_id','parent_account_id','labels','source_version','updated_at']", "old_row ?& ARRAY['parent_project_id','parent_account_id','labels','access_labels','source_version','updated_at']"],
            ["old_row-ARRAY['object_type','object_id','parent_project_id','parent_account_id','labels','source_version','updated_at']", "old_row-ARRAY['object_type','object_id','parent_project_id','parent_account_id','labels','access_labels','source_version','updated_at']"],
            ["OR jsonb_typeof(old_row->'labels') IS DISTINCT FROM 'object'", "OR jsonb_typeof(old_row->'labels') IS DISTINCT FROM 'object'\n OR jsonb_typeof(old_row->'access_labels') IS DISTINCT FROM 'object'"],
            ["'parent_account_id',account_id,'labels',p_command->'labels','source_version',version_value,'updated_at',p_transaction_at);", "'parent_account_id',account_id,'labels',p_command->'labels','access_labels','{}'::jsonb,'source_version',version_value,'updated_at',p_transaction_at);"],
            ["new_row:=old_row||attempt;applied:=true;", "new_row:=old_row||(attempt-'access_labels');applied:=true;"]
            ]$patch$::jsonb
        ),
        (
            '_authority_crud_storage_v3()',
            '5e21095177e65e55c600edb429a1ed9d55db08e1cd85908c06e701646c344f1e',
            '762fb1c24b83c085045a76deb1ebc3bb8a5abc527af11097e1bb38b022c82ece',
            $patch$[
            ["2e4cf1562674897a696483469505925ba5862b6fe0422f663b330eb96f237b9e", "092aea9c77c443b16de6c595ee2aeca2d22984fdbaf54831faad5b38659ce11d"],
            ["bc276ed48b9a8e9d4eeb6cb472bfbda1a1a400dd8b34992f391f9423143272fc", "a0290994e32a6eb0a8c753b3be6bff865afcb3a40d4a6f9dafcef0aa1c7beb3c"],
            ["5d47e24c50baaa1619a6cfb2198255c248fec06d535e13febacf7078c6aeae64", "5b08a8fb6bc43f571427993195d90b880c52fb2cdce91e29ead346579152eeb9"],
            ["909c304c45925ad0cee62e8ddc462b381778fffd89739e36b99195bea4f3b6f7", "4fd40a4e10d3a8a31dfd02e02840da2a3ff31b45f2416c147c4f3e38d79f1b21"]
            ]$patch$::jsonb
        ),
        (
            '_authority_full_contract_storage_v3()',
            '1b7b404b55d7b4a3f0537f1b00bb925b6aa6bceeb2f3ff4ea2fc736eda5a677b',
            'b9ecc56df1363970615aac9852ce65d707533034a1ded0674d3c3a8e80591361',
            $patch$[
            ["5e21095177e65e55c600edb429a1ed9d55db08e1cd85908c06e701646c344f1e", "762fb1c24b83c085045a76deb1ebc3bb8a5abc527af11097e1bb38b022c82ece"]
            ]$patch$::jsonb
        )
    ) AS changes(signature, before_sha, after_sha, substitutions) LOOP
        fn := pg_catalog.to_regprocedure('kaname.' || item.signature);
        SELECT p.prosrc INTO STRICT old_body FROM pg_catalog.pg_proc p WHERE p.oid=fn;
        IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(old_body,'UTF8')),'hex') IS DISTINCT FROM item.before_sha THEN
            RAISE EXCEPTION 'исходное тело функции % не соответствует этой миграции', item.signature USING ERRCODE='55000';
        END IF;
        new_body := old_body;
        FOR replacement IN SELECT value FROM pg_catalog.jsonb_array_elements(item.substitutions) LOOP
            needle := replacement->>0;
            IF length(new_body)-length(replace(new_body,needle,'')) IS DISTINCT FROM length(needle) THEN
                RAISE EXCEPTION 'фрагмент тела функции % не уникален', item.signature USING ERRCODE='55000';
            END IF;
            new_body := replace(new_body,needle,replacement->>1);
        END LOOP;
        IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(new_body,'UTF8')),'hex') IS DISTINCT FROM item.after_sha THEN
            RAISE EXCEPTION 'расчётное тело функции % изменилось', item.signature USING ERRCODE='55000';
        END IF;
        -- PostgreSQL восстанавливает сигнатуру и настройки, CREATE OR REPLACE
        -- сохраняет owner/ACL. Меняется ровно одно полное тело с известным SHA.
        definition := pg_catalog.pg_get_functiondef(fn);
        IF length(definition)-length(replace(definition,old_body,'')) IS DISTINCT FROM length(old_body) THEN
            RAISE EXCEPTION 'определение функции % не содержит единственного исходного тела', item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,old_body,new_body);
        IF (SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc,'UTF8')),'hex')
            FROM pg_catalog.pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.after_sha THEN
            RAISE EXCEPTION 'установленное тело функции % не совпадает с расчётным', item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
        RAISE EXCEPTION 'несогласованное состояние после обновления образов доступа' USING ERRCODE='55000';
    END IF;
END
$access_label_create_images$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $access_label_create_images$
DECLARE
    item record;
    replacement jsonb;
    fn regprocedure;
    old_body text;
    new_body text;
    definition text;
    needle text;
BEGIN
    PERFORM kaname.authority_protocol_drain();
    IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
        RAISE EXCEPTION 'несогласованное состояние перед обновлением образов доступа' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
        (
            '_authority_full_contract_storage_v3()',
            'b9ecc56df1363970615aac9852ce65d707533034a1ded0674d3c3a8e80591361',
            '1b7b404b55d7b4a3f0537f1b00bb925b6aa6bceeb2f3ff4ea2fc736eda5a677b',
            $patch$[
            ["762fb1c24b83c085045a76deb1ebc3bb8a5abc527af11097e1bb38b022c82ece", "5e21095177e65e55c600edb429a1ed9d55db08e1cd85908c06e701646c344f1e"]
            ]$patch$::jsonb
        ),
        (
            '_authority_crud_storage_v3()',
            '762fb1c24b83c085045a76deb1ebc3bb8a5abc527af11097e1bb38b022c82ece',
            '5e21095177e65e55c600edb429a1ed9d55db08e1cd85908c06e701646c344f1e',
            $patch$[
            ["4fd40a4e10d3a8a31dfd02e02840da2a3ff31b45f2416c147c4f3e38d79f1b21", "909c304c45925ad0cee62e8ddc462b381778fffd89739e36b99195bea4f3b6f7"],
            ["5b08a8fb6bc43f571427993195d90b880c52fb2cdce91e29ead346579152eeb9", "5d47e24c50baaa1619a6cfb2198255c248fec06d535e13febacf7078c6aeae64"],
            ["a0290994e32a6eb0a8c753b3be6bff865afcb3a40d4a6f9dafcef0aa1c7beb3c", "bc276ed48b9a8e9d4eeb6cb472bfbda1a1a400dd8b34992f391f9423143272fc"],
            ["092aea9c77c443b16de6c595ee2aeca2d22984fdbaf54831faad5b38659ce11d", "2e4cf1562674897a696483469505925ba5862b6fe0422f663b330eb96f237b9e"]
            ]$patch$::jsonb
        ),
        (
            '_authority_resource_registration_mirror_images_v2(jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz)',
            '4fd40a4e10d3a8a31dfd02e02840da2a3ff31b45f2416c147c4f3e38d79f1b21',
            '909c304c45925ad0cee62e8ddc462b381778fffd89739e36b99195bea4f3b6f7',
            $patch$[
            ["new_row:=old_row||(attempt-'access_labels');applied:=true;", "new_row:=old_row||attempt;applied:=true;"],
            ["'parent_account_id',account_id,'labels',p_command->'labels','access_labels','{}'::jsonb,'source_version',version_value,'updated_at',p_transaction_at);", "'parent_account_id',account_id,'labels',p_command->'labels','source_version',version_value,'updated_at',p_transaction_at);"],
            ["OR jsonb_typeof(old_row->'labels') IS DISTINCT FROM 'object'\n OR jsonb_typeof(old_row->'access_labels') IS DISTINCT FROM 'object'", "OR jsonb_typeof(old_row->'labels') IS DISTINCT FROM 'object'"],
            ["old_row-ARRAY['object_type','object_id','parent_project_id','parent_account_id','labels','access_labels','source_version','updated_at']", "old_row-ARRAY['object_type','object_id','parent_project_id','parent_account_id','labels','source_version','updated_at']"],
            ["old_row ?& ARRAY['parent_project_id','parent_account_id','labels','access_labels','source_version','updated_at']", "old_row ?& ARRAY['parent_project_id','parent_account_id','labels','source_version','updated_at']"]
            ]$patch$::jsonb
        ),
        (
            'authority_role_sequence_prepare_v3(jsonb,integer,integer)',
            '5b08a8fb6bc43f571427993195d90b880c52fb2cdce91e29ead346579152eeb9',
            '5d47e24c50baaa1619a6cfb2198255c248fec06d535e13febacf7078c6aeae64',
            $patch$[
            ["'retired_at',NULL,'retired_reason',NULL,'retired_by',NULL,'access_labels','{}'::jsonb,'created_at',root_stamp,'updated_at',root_stamp)));", "'retired_at',NULL,'retired_reason',NULL,'retired_by',NULL,'created_at',root_stamp,'updated_at',root_stamp)));"]
            ]$patch$::jsonb
        ),
        (
            'authority_binding_sequence_prepare_v3(text,jsonb)',
            'a0290994e32a6eb0a8c753b3be6bff865afcb3a40d4a6f9dafcef0aa1c7beb3c',
            'bc276ed48b9a8e9d4eeb6cb472bfbda1a1a400dd8b34992f391f9423143272fc',
            $patch$[
            ["'revocation_reason',NULL,'grant_capability_version',0,'access_labels','{}'::jsonb)));", "'revocation_reason',NULL,'grant_capability_version',0)));"]
            ]$patch$::jsonb
        ),
        (
            '_authority_crud_domain_images_v3(jsonb,jsonb,jsonb,timestamptz)',
            '092aea9c77c443b16de6c595ee2aeca2d22984fdbaf54831faad5b38659ce11d',
            '2e4cf1562674897a696483469505925ba5862b6fe0422f663b330eb96f237b9e',
            $patch$[
            ["'scope',2,'deletion_protection',true,'labels','{}'::jsonb,'access_labels','{}'::jsonb,'target',jsonb_build_object('allInScope',true),", "'scope',2,'deletion_protection',true,'labels','{}'::jsonb,'target',jsonb_build_object('allInScope',true),"],
            ["'labels',coalesce(nullif(request->'Labels','null'::jsonb),'{}'::jsonb),'access_labels','{}'::jsonb,'created_at',p_at);", "'labels',coalesce(nullif(request->'Labels','null'::jsonb),'{}'::jsonb),'created_at',p_at);"]
            ]$patch$::jsonb
        )
    ) AS changes(signature, before_sha, after_sha, substitutions) LOOP
        fn := pg_catalog.to_regprocedure('kaname.' || item.signature);
        SELECT p.prosrc INTO STRICT old_body FROM pg_catalog.pg_proc p WHERE p.oid=fn;
        IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(old_body,'UTF8')),'hex') IS DISTINCT FROM item.before_sha THEN
            RAISE EXCEPTION 'исходное тело функции % не соответствует этой миграции', item.signature USING ERRCODE='55000';
        END IF;
        new_body := old_body;
        FOR replacement IN SELECT value FROM pg_catalog.jsonb_array_elements(item.substitutions) LOOP
            needle := replacement->>0;
            IF length(new_body)-length(replace(new_body,needle,'')) IS DISTINCT FROM length(needle) THEN
                RAISE EXCEPTION 'фрагмент тела функции % не уникален', item.signature USING ERRCODE='55000';
            END IF;
            new_body := replace(new_body,needle,replacement->>1);
        END LOOP;
        IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(new_body,'UTF8')),'hex') IS DISTINCT FROM item.after_sha THEN
            RAISE EXCEPTION 'расчётное тело функции % изменилось', item.signature USING ERRCODE='55000';
        END IF;
        -- PostgreSQL восстанавливает сигнатуру и настройки, CREATE OR REPLACE
        -- сохраняет owner/ACL. Меняется ровно одно полное тело с известным SHA.
        definition := pg_catalog.pg_get_functiondef(fn);
        IF length(definition)-length(replace(definition,old_body,'')) IS DISTINCT FROM length(old_body) THEN
            RAISE EXCEPTION 'определение функции % не содержит единственного исходного тела', item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,old_body,new_body);
        IF (SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc,'UTF8')),'hex')
            FROM pg_catalog.pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.after_sha THEN
            RAISE EXCEPTION 'установленное тело функции % не совпадает с расчётным', item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
        RAISE EXCEPTION 'несогласованное состояние после обновления образов доступа' USING ERRCODE='55000';
    END IF;
END
$access_label_create_images$;
-- +goose StatementEnd
