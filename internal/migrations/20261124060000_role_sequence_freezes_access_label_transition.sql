-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- По точным образам роли готовится закрытая проекция до фиксации времени
-- решения. Неприменённая проекция блокирует завершение транзакции.

-- +goose Up
-- +goose StatementBegin
DO $access_label_role_sequence$
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
        ('authority_access_label_role_compile_v1(jsonb)','6874aeab77f7368b78ec31059329e463a729a61df0a1e9870dc02823b8c9c145'),
        ('authority_access_label_role_transition_prepare_v1(jsonb,jsonb,integer,integer)','b52c1fd273d1b169ae22aa313237fc573b28c11b3b0a16e72a6ede67f31e37a3'),
        ('authority_access_label_definition_hold_v1(text,text,text,text,text,uuid,bigint,text,text,text)','b859960574d437d1422b8bf6e2a46eff5c76967dcdbb50c709056dbefb69c912')
    ) AS dependencies(signature,digest) LOOP
        fn := pg_catalog.to_regprocedure('kaname.' || item.signature);
        SELECT p.prosrc INTO STRICT old_body FROM pg_catalog.pg_proc p WHERE p.oid=fn;
        IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(old_body,'UTF8')),'hex') IS DISTINCT FROM item.digest THEN
            RAISE EXCEPTION 'изменилось тело закрытой функции accessLabels %', item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    FOR item IN SELECT * FROM (VALUES
        (
            'authority_role_sequence_prepare_v3(jsonb,integer,integer)',
            '5b08a8fb6bc43f571427993195d90b880c52fb2cdce91e29ead346579152eeb9',
            '15e6d0b5ff8dd88de51c684e4a7a1df23e460ed3a4c36a7781fd444be5f68550',
            $patch$[
  [
    " scanned integer:=1;reads integer:=1;carriers integer:=0;",
    " scanned integer:=1;reads integer:=1;carriers integer:=0;\n access_label_transition jsonb;access_label_frozen jsonb:='{}';access_label_needed boolean;"
  ],
  [
    " cost:=kaname._authority_sequence_reserve_v3('role',maximum,p_reads-reads);",
    " -- Проверяем изменение по фактическим образам роли.\n IF creation OR old_role->'rules' IS DISTINCT FROM new_role->'rules' THEN\n  -- Прежние правила без этой оси сохраняют свой формат и пределы.\n  -- Сохранённая проекция требует сверки даже при пустой новой стороне.\n  SELECT EXISTS(SELECT 1\n   FROM jsonb_array_elements(coalesce(old_role->'rules','[]'::jsonb)||(new_role->'rules')) r\n   WHERE (r.value->>'module'='iam' AND r.value->'resources' ? 'accessLabel')\n    OR EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(r.value->'children')='array'\n      THEN r.value->'children' ELSE '[]'::jsonb END) c\n     WHERE coalesce(nullif(c.value->>'module',''),r.value->>'module')='iam'\n      AND c.value->'resources' ? 'accessLabel')) INTO access_label_needed;\n  IF NOT creation AND NOT access_label_needed THEN\n   IF reads>=p_reads THEN RAISE EXCEPTION 'role access label probe read budget' USING ERRCODE='54000';END IF;\n   SELECT EXISTS(SELECT 1 FROM kaname.authority_role_access_label_rule a\n    WHERE a.role_id=new_role->>'id') INTO access_label_needed;\n   reads:=reads+1;\n   IF access_label_needed THEN scanned:=scanned+1;END IF;\n  END IF;\n  IF access_label_needed THEN\n   access_label_transition:=kaname.authority_access_label_role_transition_prepare_v1(\n    old_role,new_role,p_rows-scanned,p_reads-reads);\n   scanned:=scanned+(access_label_transition->>'rows')::integer;\n   reads:=reads+(access_label_transition->>'reads')::integer;\n   IF access_label_transition->'old_projection'<>'[]'::jsonb\n    OR access_label_transition->'new_projection'<>'[]'::jsonb THEN\n    access_label_frozen:=jsonb_build_object('mode','access_label_transition',\n     'access_label_transition',access_label_transition);\n   END IF;\n  END IF;\n END IF;\n IF scanned>p_rows OR reads>p_reads THEN RAISE EXCEPTION 'role access label shared budget' USING ERRCODE='54000';END IF;\n cost:=kaname._authority_sequence_reserve_v3('role',maximum,p_reads-reads);"
  ],
  [
    "'create',creation,'request',p_input,'stamp',root_stamp,'expiry',expiry));",
    "'create',creation,'request',p_input,'stamp',root_stamp,'expiry',expiry)||access_label_frozen);"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_sequence_complete_v3()',
            'c9f728c4492acf65f92ea6a6f411b3af85e63e765c5226bbf3ea1e80fd9291d1',
            '7c12702a047d071c672f2e3586297a59110ad6c4f7d696801293436a96dea298',
            $patch$[
  [
    " IF program IS NULL THEN RETURN;END IF;",
    " IF program IS NULL THEN RETURN;END IF;\n -- Режим берётся из проверенного заголовка owner program.\n IF program->>'family'='role' AND program#>>'{frozen,mode}'='access_label_transition' THEN\n  RAISE EXCEPTION 'role access label transition requires an atomic projection writer' USING ERRCODE='42501';\n END IF;"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_crud_storage_v3()',
            'eb6275fc7cf187806dd647806770c1ab7f9ca4426f7dd2d93951664ab04eee9a',
            'c9f577dce957fc522b4f32a0b421c55b6512d911e7260bf5b753d96b3aff1295',
            $patch$[
  [
    "5b08a8fb6bc43f571427993195d90b880c52fb2cdce91e29ead346579152eeb9",
    "15e6d0b5ff8dd88de51c684e4a7a1df23e460ed3a4c36a7781fd444be5f68550"
  ],
  [
    "c9f728c4492acf65f92ea6a6f411b3af85e63e765c5226bbf3ea1e80fd9291d1",
    "7c12702a047d071c672f2e3586297a59110ad6c4f7d696801293436a96dea298"
  ],
  [
    " ('_authority_sequence_complete_v3()','7c12702a047d071c672f2e3586297a59110ad6c4f7d696801293436a96dea298',true,'v',true,'private'),",
    " ('_authority_sequence_complete_v3()','7c12702a047d071c672f2e3586297a59110ad6c4f7d696801293436a96dea298',true,'v',true,'private'),\n ('authority_access_label_role_compile_v1(jsonb)','6874aeab77f7368b78ec31059329e463a729a61df0a1e9870dc02823b8c9c145',false,'v',true,'private'),\n ('authority_access_label_role_transition_prepare_v1(jsonb,jsonb,integer,integer)','b52c1fd273d1b169ae22aa313237fc573b28c11b3b0a16e72a6ede67f31e37a3',false,'v',true,'private'),\n ('authority_access_label_definition_hold_v1(text,text,text,text,text,uuid,bigint,text,text,text)','b859960574d437d1422b8bf6e2a46eff5c76967dcdbb50c709056dbefb69c912',false,'v',true,'private'),"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_full_contract_storage_v3()',
            '49b7a806ea6c846fe35fd9777dd641f8f0fe50bdb2accaacc70624de5ce43790',
            '6781bdef76d9603bcea19a9cab4d574c50b1e9c35dcb0da2db70b7f4a67941b4',
            $patch$[
  [
    "eb6275fc7cf187806dd647806770c1ab7f9ca4426f7dd2d93951664ab04eee9a",
    "c9f577dce957fc522b4f32a0b421c55b6512d911e7260bf5b753d96b3aff1295"
  ]
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
$access_label_role_sequence$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $access_label_role_sequence$
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
        ('authority_access_label_role_compile_v1(jsonb)','6874aeab77f7368b78ec31059329e463a729a61df0a1e9870dc02823b8c9c145'),
        ('authority_access_label_role_transition_prepare_v1(jsonb,jsonb,integer,integer)','b52c1fd273d1b169ae22aa313237fc573b28c11b3b0a16e72a6ede67f31e37a3'),
        ('authority_access_label_definition_hold_v1(text,text,text,text,text,uuid,bigint,text,text,text)','b859960574d437d1422b8bf6e2a46eff5c76967dcdbb50c709056dbefb69c912')
    ) AS dependencies(signature,digest) LOOP
        fn := pg_catalog.to_regprocedure('kaname.' || item.signature);
        SELECT p.prosrc INTO STRICT old_body FROM pg_catalog.pg_proc p WHERE p.oid=fn;
        IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(old_body,'UTF8')),'hex') IS DISTINCT FROM item.digest THEN
            RAISE EXCEPTION 'изменилось тело закрытой функции accessLabels %', item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    FOR item IN SELECT * FROM (VALUES
        (
            '_authority_full_contract_storage_v3()',
            '6781bdef76d9603bcea19a9cab4d574c50b1e9c35dcb0da2db70b7f4a67941b4',
            '49b7a806ea6c846fe35fd9777dd641f8f0fe50bdb2accaacc70624de5ce43790',
            $patch$[
  [
    "c9f577dce957fc522b4f32a0b421c55b6512d911e7260bf5b753d96b3aff1295",
    "eb6275fc7cf187806dd647806770c1ab7f9ca4426f7dd2d93951664ab04eee9a"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_crud_storage_v3()',
            'c9f577dce957fc522b4f32a0b421c55b6512d911e7260bf5b753d96b3aff1295',
            'eb6275fc7cf187806dd647806770c1ab7f9ca4426f7dd2d93951664ab04eee9a',
            $patch$[
  [
    " ('_authority_sequence_complete_v3()','7c12702a047d071c672f2e3586297a59110ad6c4f7d696801293436a96dea298',true,'v',true,'private'),\n ('authority_access_label_role_compile_v1(jsonb)','6874aeab77f7368b78ec31059329e463a729a61df0a1e9870dc02823b8c9c145',false,'v',true,'private'),\n ('authority_access_label_role_transition_prepare_v1(jsonb,jsonb,integer,integer)','b52c1fd273d1b169ae22aa313237fc573b28c11b3b0a16e72a6ede67f31e37a3',false,'v',true,'private'),\n ('authority_access_label_definition_hold_v1(text,text,text,text,text,uuid,bigint,text,text,text)','b859960574d437d1422b8bf6e2a46eff5c76967dcdbb50c709056dbefb69c912',false,'v',true,'private'),",
    " ('_authority_sequence_complete_v3()','7c12702a047d071c672f2e3586297a59110ad6c4f7d696801293436a96dea298',true,'v',true,'private'),"
  ],
  [
    "7c12702a047d071c672f2e3586297a59110ad6c4f7d696801293436a96dea298",
    "c9f728c4492acf65f92ea6a6f411b3af85e63e765c5226bbf3ea1e80fd9291d1"
  ],
  [
    "15e6d0b5ff8dd88de51c684e4a7a1df23e460ed3a4c36a7781fd444be5f68550",
    "5b08a8fb6bc43f571427993195d90b880c52fb2cdce91e29ead346579152eeb9"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_sequence_complete_v3()',
            '7c12702a047d071c672f2e3586297a59110ad6c4f7d696801293436a96dea298',
            'c9f728c4492acf65f92ea6a6f411b3af85e63e765c5226bbf3ea1e80fd9291d1',
            $patch$[
  [
    " IF program IS NULL THEN RETURN;END IF;\n -- Режим берётся из проверенного заголовка owner program.\n IF program->>'family'='role' AND program#>>'{frozen,mode}'='access_label_transition' THEN\n  RAISE EXCEPTION 'role access label transition requires an atomic projection writer' USING ERRCODE='42501';\n END IF;",
    " IF program IS NULL THEN RETURN;END IF;"
  ]
]$patch$::jsonb
        ),
        (
            'authority_role_sequence_prepare_v3(jsonb,integer,integer)',
            '15e6d0b5ff8dd88de51c684e4a7a1df23e460ed3a4c36a7781fd444be5f68550',
            '5b08a8fb6bc43f571427993195d90b880c52fb2cdce91e29ead346579152eeb9',
            $patch$[
  [
    "'create',creation,'request',p_input,'stamp',root_stamp,'expiry',expiry)||access_label_frozen);",
    "'create',creation,'request',p_input,'stamp',root_stamp,'expiry',expiry));"
  ],
  [
    " -- Проверяем изменение по фактическим образам роли.\n IF creation OR old_role->'rules' IS DISTINCT FROM new_role->'rules' THEN\n  -- Прежние правила без этой оси сохраняют свой формат и пределы.\n  -- Сохранённая проекция требует сверки даже при пустой новой стороне.\n  SELECT EXISTS(SELECT 1\n   FROM jsonb_array_elements(coalesce(old_role->'rules','[]'::jsonb)||(new_role->'rules')) r\n   WHERE (r.value->>'module'='iam' AND r.value->'resources' ? 'accessLabel')\n    OR EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(r.value->'children')='array'\n      THEN r.value->'children' ELSE '[]'::jsonb END) c\n     WHERE coalesce(nullif(c.value->>'module',''),r.value->>'module')='iam'\n      AND c.value->'resources' ? 'accessLabel')) INTO access_label_needed;\n  IF NOT creation AND NOT access_label_needed THEN\n   IF reads>=p_reads THEN RAISE EXCEPTION 'role access label probe read budget' USING ERRCODE='54000';END IF;\n   SELECT EXISTS(SELECT 1 FROM kaname.authority_role_access_label_rule a\n    WHERE a.role_id=new_role->>'id') INTO access_label_needed;\n   reads:=reads+1;\n   IF access_label_needed THEN scanned:=scanned+1;END IF;\n  END IF;\n  IF access_label_needed THEN\n   access_label_transition:=kaname.authority_access_label_role_transition_prepare_v1(\n    old_role,new_role,p_rows-scanned,p_reads-reads);\n   scanned:=scanned+(access_label_transition->>'rows')::integer;\n   reads:=reads+(access_label_transition->>'reads')::integer;\n   IF access_label_transition->'old_projection'<>'[]'::jsonb\n    OR access_label_transition->'new_projection'<>'[]'::jsonb THEN\n    access_label_frozen:=jsonb_build_object('mode','access_label_transition',\n     'access_label_transition',access_label_transition);\n   END IF;\n  END IF;\n END IF;\n IF scanned>p_rows OR reads>p_reads THEN RAISE EXCEPTION 'role access label shared budget' USING ERRCODE='54000';END IF;\n cost:=kaname._authority_sequence_reserve_v3('role',maximum,p_reads-reads);",
    " cost:=kaname._authority_sequence_reserve_v3('role',maximum,p_reads-reads);"
  ],
  [
    " scanned integer:=1;reads integer:=1;carriers integer:=0;\n access_label_transition jsonb;access_label_frozen jsonb:='{}';access_label_needed boolean;",
    " scanned integer:=1;reads integer:=1;carriers integer:=0;"
  ]
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
$access_label_role_sequence$;
-- +goose StatementEnd
