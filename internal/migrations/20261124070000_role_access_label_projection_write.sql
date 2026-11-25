-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Применение проекции связано с фактическим источником журнала роли.
-- Для удаления заранее подготавливается точная проекция OLD → NULL.

-- +goose Up
SELECT kaname.authority_protocol_drain();
LOCK TABLE kaname.authority_role_access_label_rule IN ACCESS EXCLUSIVE MODE;

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_access_label_role_projection_apply_v1(
    p_origin jsonb, p_old_xmin text, p_old_ctid text
) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
    program jsonb;
    proof jsonb;
    transition jsonb;
    target_role_id text;
    actual jsonb;
    expected integer;
    changed integer;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    SELECT q.proof,q.header INTO STRICT proof,program FROM kaname._authority_sequence_probe_v3() q;
    IF pg_trigger_depth()<1 OR proof->>'writer_contract' IS DISTINCT FROM '2'
       OR proof->>'kind' IS DISTINCT FROM 'role' OR proof->>'purpose' IS DISTINCT FROM 'decision'
       OR program->>'family' IS DISTINCT FROM 'role'
       OR program#>>'{frozen,mode}' IS DISTINCT FROM 'access_label_transition'
       OR jsonb_typeof(program->'selected') IS DISTINCT FROM 'array'
       OR p_origin->>'table' IS DISTINCT FROM 'roles' OR p_origin->>'when' IS DISTINCT FROM 'AFTER'
       OR coalesce(p_origin->>'operation','') NOT IN ('INSERT','UPDATE') THEN
        RAISE EXCEPTION 'access label projection requires a finalized role origin' USING ERRCODE='42501';
    END IF;
    SELECT s.frozen->'access_label_transition' INTO STRICT transition
    FROM pg_temp.kaname_authority_sequence_program s
    WHERE s.singleton AND s.nonce=(program->>'nonce')::uuid
      AND s.frozen->>'kind'='role.mutation' AND NOT (s.frozen ? 'access_label_transition_applied');
    target_role_id:=transition->>'role_id';
    IF target_role_id IS NULL OR p_origin#>>'{new,id}' IS DISTINCT FROM target_role_id
       OR p_origin->'old' IS DISTINCT FROM transition->'old_row'
       OR p_origin->'new' IS DISTINCT FROM transition->'new_row'
       OR p_old_xmin IS DISTINCT FROM transition->>'old_xmin'
       OR p_old_ctid IS DISTINCT FROM transition->>'old_ctid'
       OR NOT EXISTS (
        SELECT 1 FROM pg_temp.kaname_authority_sequence_effects e
        WHERE e.nonce=(program->>'nonce')::uuid AND e.table_name='resource_journal'
          AND e.selected AND e.registered AND e.origin=p_origin
          AND e.origin_digest=sha256(convert_to(p_origin::text,'UTF8')))
    THEN RAISE EXCEPTION 'access label projection role origin differs' USING ERRCODE='42501';END IF;
    -- AFTER читает именно результат записи, а не предложенный образ вызывающего.
    SELECT to_jsonb(r) INTO STRICT actual FROM kaname.roles r WHERE r.id=target_role_id FOR UPDATE;
    IF actual IS DISTINCT FROM transition->'new_row' THEN
        RAISE EXCEPTION 'access label projection role row changed' USING ERRCODE='40001';
    END IF;
    IF transition->'old_projection' IS DISTINCT FROM transition->'new_projection' THEN
        -- В коротком интервале записи разрешён только штатный сторож таблицы.
        -- Внешний триггер или правило не может исполниться под этим режимом.
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_class c
            WHERE c.oid='kaname.authority_role_access_label_rule'::regclass
              AND c.relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)
              AND c.relkind='r' AND c.relpersistence='p'
              AND NOT (c.relhasrules OR c.relrowsecurity)
              AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(coalesce(c.relacl,pg_catalog.acldefault('r',c.relowner))) a
                              WHERE a.grantee<>c.relowner)
              AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute v CROSS JOIN LATERAL pg_catalog.aclexplode(v.attacl) a
                              WHERE v.attrelid=c.oid AND a.grantee<>c.relowner)
              AND (SELECT count(*) FROM pg_catalog.pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal)=1
              AND EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t
                          WHERE t.tgrelid=c.oid AND NOT t.tgisinternal
                            AND t.tgname='authority_role_access_label_rule_closed' AND t.tgtype=62
                            AND t.tgenabled='O' AND t.tgqual IS NULL
                            AND t.tgfoid='kaname.authority_role_access_label_rule_closed_v1()'::regprocedure)
        ) THEN RAISE EXCEPTION 'access label projection storage changed' USING ERRCODE='42501';END IF;
        -- Короткий допуск хранится в той же закрытой таблице программы. При
        -- исключении изменение режима и все строки откатываются вместе.
        UPDATE pg_temp.kaname_authority_sequence_program s SET frozen_mode='access_label_projection_write'
        WHERE s.singleton AND s.nonce=(program->>'nonce')::uuid;
        IF jsonb_array_length(transition->'old_projection')>0 THEN
            WITH removed AS MATERIALIZED (
                SELECT value FROM jsonb_array_elements(transition->'old_projection')
                EXCEPT SELECT value FROM jsonb_array_elements(transition->'new_projection')
            ), applied AS (
                DELETE FROM ONLY kaname.authority_role_access_label_rule p USING removed d
                WHERE p.role_id=target_role_id AND p.rule_fp=d.value->>0 AND p.definition_id=(d.value->>1)::uuid
                RETURNING 1
            ) SELECT (SELECT count(*) FROM removed),(SELECT count(*) FROM applied) INTO expected,changed;
            IF changed<>expected THEN
                RAISE EXCEPTION 'access label projection OLD delta changed' USING ERRCODE='40001';
            END IF;
        END IF;
        INSERT INTO kaname.authority_role_access_label_rule(role_id,rule_fp,definition_id)
        SELECT target_role_id,d.value->>0,(d.value->>1)::uuid FROM (
            SELECT value FROM jsonb_array_elements(transition->'new_projection')
            EXCEPT SELECT value FROM jsonb_array_elements(transition->'old_projection')
        ) d ORDER BY (d.value->>0) COLLATE "C",(d.value->>1)::uuid;
    END IF;
    UPDATE pg_temp.kaname_authority_sequence_program s
    SET frozen_mode='access_label_transition',
        frozen=s.frozen||jsonb_build_object('access_label_transition_applied',true)
    WHERE s.singleton AND s.nonce=(program->>'nonce')::uuid;
    -- Обязательство остаётся в программе. Существующий completion отклоняет
    -- commit до подключения проверки полномочий и признака применения.
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$
DECLARE
    signature constant text := 'kaname.authority_access_label_role_projection_apply_v1(jsonb,text,text)';
    grantee record;
BEGIN
    FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
        CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
        WHERE p.oid=to_regprocedure(signature) AND a.grantee<>p.proowner
    LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',signature,
            CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $access_label_projection_patch$
DECLARE
    item record;
    replacement jsonb;
    fn regprocedure;
    old_body text;
    new_body text;
    definition text;
    needle text;
BEGIN
    IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
        RAISE EXCEPTION 'несогласованное состояние перед изменением записи проекции доступа' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
        (
            'authority_role_access_label_rule_closed_v1()',
            '6734da847536b6e50a1b2806498ff25311e481b03f8430f1ee792e533633ce7e',
            '9215a52e70f6989a1aa6ebc8f4d5cdc05cc78799c49688eb641eb475ac5dce67',
            $patch$[
  [
    "\nBEGIN\n    RAISE EXCEPTION 'access label role projection requires a protected writer'\n        USING ERRCODE = '42501';\nEND;\n",
    "\nDECLARE program jsonb;\nBEGIN\n    IF TG_TABLE_SCHEMA='kaname' AND TG_TABLE_NAME='authority_role_access_label_rule'\n       AND TG_LEVEL='STATEMENT' AND TG_WHEN='BEFORE' AND TG_OP IN ('INSERT','DELETE')\n       AND pg_trigger_depth()>1 AND to_regclass('pg_temp.kaname_authority_sequence_program') IS NOT NULL THEN\n        PERFORM kaname.authority_protocol_require_owner();\n        program:=kaname._authority_sequence_header_v3();\n        IF program->>'family'='role' AND jsonb_typeof(program->'selected')='array'\n           AND program#>>'{frozen,mode}'='access_label_projection_write' THEN\n            RETURN NULL;\n        END IF;\n    END IF;\n    RAISE EXCEPTION 'access label role projection requires a protected writer' USING ERRCODE='42501';\nEND;\n"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_resource_crud_prepare_v3(jsonb,integer,integer)',
            'ee22d1a0007376a262864613f3cef81893f76d70f2ceae94fe2e672273914aa4',
            '8375a33475fa65f764f3b8a522185290b7b165cb9bb203d3260c3d9d887a2074',
            $patch$[
  [
    " key_value text;table_name text;tuple_rows jsonb;used_rows integer:=0;used_reads integer:=0;compiled jsonb;preview jsonb;",
    " key_value text;table_name text;tuple_rows jsonb;used_rows integer:=0;used_reads integer:=0;compiled jsonb;preview jsonb;\n access_label_old jsonb;access_label_transition jsonb;access_label_frozen jsonb:='{}';access_label_needed boolean;"
  ],
  [
    " certificate:=jsonb_build_object('intent',intent,'command',descriptor->>'command','program',program,'graph_index',maximum->'graph_index');",
    " -- Точный OLD подтверждён общим after_capture и удержан root tuple wait.\n -- Private projection не добавляется в публичный RR capture/envelope.\n IF descriptor->>'command'='role.delete' THEN\n  access_label_old:=nullif(sources#>'{primary,row}','null'::jsonb);\n  IF access_label_old IS NOT NULL THEN\n   SELECT EXISTS(SELECT 1 FROM jsonb_array_elements(access_label_old->'rules') r\n    WHERE (r.value->>'module'='iam' AND r.value->'resources' ? 'accessLabel')\n     OR EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(r.value->'children')='array'\n       THEN r.value->'children' ELSE '[]'::jsonb END) c\n      WHERE coalesce(nullif(c.value->>'module',''),r.value->>'module')='iam'\n       AND c.value->'resources' ? 'accessLabel')) INTO access_label_needed;\n   IF NOT access_label_needed THEN\n    IF used_reads>=p_reads THEN RAISE EXCEPTION 'role delete access label probe budget' USING ERRCODE='54000';END IF;\n    SELECT EXISTS(SELECT 1 FROM kaname.authority_role_access_label_rule a\n     WHERE a.role_id=descriptor->>'id') INTO access_label_needed;\n    used_reads:=used_reads+1;\n    IF access_label_needed THEN used_rows:=used_rows+1;END IF;\n   END IF;\n   IF access_label_needed THEN\n    access_label_transition:=kaname.authority_access_label_role_transition_prepare_v1(\n     access_label_old,NULL,p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(access_label_transition->>'rows')::integer;\n    used_reads:=used_reads+(access_label_transition->>'reads')::integer;\n    IF access_label_transition->'old_xmin' IS DISTINCT FROM sources#>'{primary,xmin}'\n     OR access_label_transition->'old_ctid' IS DISTINCT FROM sources#>'{primary,ctid}' THEN\n     RAISE EXCEPTION 'role delete access label OLD version changed' USING ERRCODE='P1034';END IF;\n    held_relations:=held_relations||jsonb_build_array(jsonb_build_object(\n     'oid','kaname.authority_role_access_label_rule'::regclass::oid,'mode','RowExclusiveLock'));\n    IF access_label_transition->'old_projection'<>'[]'::jsonb THEN\n     held_relations:=held_relations||jsonb_build_array(jsonb_build_object(\n      'oid','kaname.authority_access_label_definition'::regclass::oid,'mode','RowShareLock'));\n     access_label_frozen:=jsonb_build_object('access_label_transition',access_label_transition);\n    END IF;\n   END IF;\n  END IF;\n END IF;\n certificate:=jsonb_build_object('intent',intent,'command',descriptor->>'command','program',program,'graph_index',maximum->'graph_index');"
  ],
  [
    "'prepared',jsonb_build_object('reserved',reserved->'reserved','held_legacy_keys',legacy_keys),",
    "'prepared',jsonb_build_object('reserved',reserved->'reserved','held_legacy_keys',legacy_keys)||access_label_frozen,"
  ],
  [
    " IF used_rows>p_rows OR used_reads>p_reads OR jsonb_array_length(held_advisory)>4096 OR jsonb_array_length(held_relations)>256 THEN",
    " IF (access_label_frozen<>'{}'::jsonb AND octet_length((compiled->'prepared')::text)>67108864)\n OR used_rows>p_rows OR used_reads>p_reads OR jsonb_array_length(held_advisory)>4096 OR jsonb_array_length(held_relations)>256 THEN"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_resource_crud_materialize_v3(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)',
            'b3e2ac3c0942fa7957aa6ecb234c39b388dc80881cdd23545c774cfd05112dff',
            'eed1441aa010ff34d292704ba3aa38bf54e01d529f88dd15d55bff11373bb21a',
            $patch$[
  [
    "DECLARE descriptor jsonb;program jsonb;domain_images jsonb;graph_index jsonb;physical jsonb;packed jsonb;",
    "DECLARE descriptor jsonb;program jsonb;domain_images jsonb;graph_index jsonb;physical jsonb;packed jsonb;\n access_label_transition jsonb;access_label_frozen jsonb:='{}';"
  ],
  [
    " program:=kaname._authority_crud_command_plan_v3(p_intent,p_sources);",
    " -- После clock только проверка и перенос owner-prepared обязанности.\n -- Новых чтений, блокировок и перекомпиляции правил здесь нет.\n IF p_prepared ? 'access_label_transition' THEN\n  access_label_transition:=p_prepared->'access_label_transition';\n  IF descriptor->>'command' IS DISTINCT FROM 'role.delete'\n   OR jsonb_typeof(access_label_transition) IS DISTINCT FROM 'object'\n   OR access_label_transition->>'role_id' IS DISTINCT FROM descriptor->>'id'\n   OR access_label_transition->'old_row' IS DISTINCT FROM p_sources#>'{primary,row}'\n   OR access_label_transition->'old_xmin' IS DISTINCT FROM p_sources#>'{primary,xmin}'\n   OR access_label_transition->'old_ctid' IS DISTINCT FROM p_sources#>'{primary,ctid}'\n   OR access_label_transition->>'old_digest' IS DISTINCT FROM\n    encode(sha256(convert_to((p_sources#>'{primary,row}')::text,'UTF8')),'hex')\n   OR access_label_transition->'new_row' IS DISTINCT FROM 'null'::jsonb\n   OR access_label_transition->'new_digest' IS DISTINCT FROM 'null'::jsonb\n   OR access_label_transition->'new_projection' IS DISTINCT FROM '[]'::jsonb\n   OR jsonb_typeof(access_label_transition->'old_projection') IS DISTINCT FROM 'array' THEN\n   RAISE EXCEPTION 'role delete access label prepared image differs' USING ERRCODE='42501';END IF;\n  IF jsonb_array_length(access_label_transition->'old_projection') NOT BETWEEN 1 AND 16384 THEN\n   RAISE EXCEPTION 'role delete access label prepared projection bound' USING ERRCODE='42501';END IF;\n  access_label_frozen:=jsonb_build_object('access_label_transition',access_label_transition);\n END IF;\n program:=kaname._authority_crud_command_plan_v3(p_intent,p_sources);"
  ],
  [
    " RETURN (packed-'body')||(packed->'body')||jsonb_build_object('held_legacy_keys',p_prepared->'held_legacy_keys');",
    " RETURN (packed-'body')||(packed->'body')||jsonb_build_object('held_legacy_keys',p_prepared->'held_legacy_keys')||access_label_frozen;"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_crud_storage_v3()',
            '89b06e9f7fcd3ba461b389ad5a1b4235a6e87ffae96ef067708905e4aa6f7dcb',
            '964ffead61a9b39cc6f09f8bd0b5b37e24ebb1440431d88741bfeec097796762',
            $patch$[
  [
    "ee22d1a0007376a262864613f3cef81893f76d70f2ceae94fe2e672273914aa4",
    "8375a33475fa65f764f3b8a522185290b7b165cb9bb203d3260c3d9d887a2074"
  ],
  [
    "b3e2ac3c0942fa7957aa6ecb234c39b388dc80881cdd23545c774cfd05112dff",
    "eed1441aa010ff34d292704ba3aa38bf54e01d529f88dd15d55bff11373bb21a"
  ],
  [
    " ('authority_access_label_definition_hold_v1(text,text,text,text,text,uuid,bigint,text,text,text)','b859960574d437d1422b8bf6e2a46eff5c76967dcdbb50c709056dbefb69c912',false,'v',true,'private'),",
    " ('authority_access_label_definition_hold_v1(text,text,text,text,text,uuid,bigint,text,text,text)','b859960574d437d1422b8bf6e2a46eff5c76967dcdbb50c709056dbefb69c912',false,'v',true,'private'),\n ('authority_role_access_label_rule_closed_v1()','9215a52e70f6989a1aa6ebc8f4d5cdc05cc78799c49688eb641eb475ac5dce67',false,'v',true,'private'),"
  ],
  [
    " ('authority_role_access_label_rule_closed_v1()','9215a52e70f6989a1aa6ebc8f4d5cdc05cc78799c49688eb641eb475ac5dce67',false,'v',true,'private'),",
    " ('authority_role_access_label_rule_closed_v1()','9215a52e70f6989a1aa6ebc8f4d5cdc05cc78799c49688eb641eb475ac5dce67',false,'v',true,'private'),\n ('authority_access_label_role_projection_apply_v1(jsonb,text,text)','8354841ae2bd79b3fe23fa6bec9aa0d04007384df6354302814b9f2696d60362',false,'v',true,'private'),"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_full_contract_storage_v3()',
            'c85b31ef0d75f7ab82995b3529011c0e6ec65d01c952fb6d0a171ccb48a228a8',
            '381f3802af54413f00c74d624af1ec32b600c8b76cd8608a82e108c1f2f8781d',
            $patch$[
  [
    "89b06e9f7fcd3ba461b389ad5a1b4235a6e87ffae96ef067708905e4aa6f7dcb",
    "964ffead61a9b39cc6f09f8bd0b5b37e24ebb1440431d88741bfeec097796762"
  ]
]$patch$::jsonb
        )
    ) AS changes(signature, before_sha, after_sha, substitutions) LOOP
        fn := pg_catalog.to_regprocedure('kaname.' || item.signature);
        IF fn IS NULL THEN RAISE EXCEPTION 'функция % для миграции отсутствует', item.signature USING ERRCODE='55000';END IF;
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
$access_label_projection_patch$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
LOCK TABLE kaname.authority_role_access_label_rule IN ACCESS EXCLUSIVE MODE;

-- +goose StatementBegin
DO $access_label_projection_patch$
DECLARE
    item record;
    replacement jsonb;
    fn regprocedure;
    old_body text;
    new_body text;
    definition text;
    needle text;
BEGIN
    IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
        RAISE EXCEPTION 'несогласованное состояние перед изменением записи проекции доступа' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
        (
            '_authority_full_contract_storage_v3()',
            '381f3802af54413f00c74d624af1ec32b600c8b76cd8608a82e108c1f2f8781d',
            'c85b31ef0d75f7ab82995b3529011c0e6ec65d01c952fb6d0a171ccb48a228a8',
            $patch$[
  [
    "964ffead61a9b39cc6f09f8bd0b5b37e24ebb1440431d88741bfeec097796762",
    "89b06e9f7fcd3ba461b389ad5a1b4235a6e87ffae96ef067708905e4aa6f7dcb"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_crud_storage_v3()',
            '964ffead61a9b39cc6f09f8bd0b5b37e24ebb1440431d88741bfeec097796762',
            '89b06e9f7fcd3ba461b389ad5a1b4235a6e87ffae96ef067708905e4aa6f7dcb',
            $patch$[
  [
    " ('authority_role_access_label_rule_closed_v1()','9215a52e70f6989a1aa6ebc8f4d5cdc05cc78799c49688eb641eb475ac5dce67',false,'v',true,'private'),\n ('authority_access_label_role_projection_apply_v1(jsonb,text,text)','8354841ae2bd79b3fe23fa6bec9aa0d04007384df6354302814b9f2696d60362',false,'v',true,'private'),",
    " ('authority_role_access_label_rule_closed_v1()','9215a52e70f6989a1aa6ebc8f4d5cdc05cc78799c49688eb641eb475ac5dce67',false,'v',true,'private'),"
  ],
  [
    " ('authority_access_label_definition_hold_v1(text,text,text,text,text,uuid,bigint,text,text,text)','b859960574d437d1422b8bf6e2a46eff5c76967dcdbb50c709056dbefb69c912',false,'v',true,'private'),\n ('authority_role_access_label_rule_closed_v1()','9215a52e70f6989a1aa6ebc8f4d5cdc05cc78799c49688eb641eb475ac5dce67',false,'v',true,'private'),",
    " ('authority_access_label_definition_hold_v1(text,text,text,text,text,uuid,bigint,text,text,text)','b859960574d437d1422b8bf6e2a46eff5c76967dcdbb50c709056dbefb69c912',false,'v',true,'private'),"
  ],
  [
    "eed1441aa010ff34d292704ba3aa38bf54e01d529f88dd15d55bff11373bb21a",
    "b3e2ac3c0942fa7957aa6ecb234c39b388dc80881cdd23545c774cfd05112dff"
  ],
  [
    "8375a33475fa65f764f3b8a522185290b7b165cb9bb203d3260c3d9d887a2074",
    "ee22d1a0007376a262864613f3cef81893f76d70f2ceae94fe2e672273914aa4"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_resource_crud_materialize_v3(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)',
            'eed1441aa010ff34d292704ba3aa38bf54e01d529f88dd15d55bff11373bb21a',
            'b3e2ac3c0942fa7957aa6ecb234c39b388dc80881cdd23545c774cfd05112dff',
            $patch$[
  [
    " RETURN (packed-'body')||(packed->'body')||jsonb_build_object('held_legacy_keys',p_prepared->'held_legacy_keys')||access_label_frozen;",
    " RETURN (packed-'body')||(packed->'body')||jsonb_build_object('held_legacy_keys',p_prepared->'held_legacy_keys');"
  ],
  [
    " -- После clock только проверка и перенос owner-prepared обязанности.\n -- Новых чтений, блокировок и перекомпиляции правил здесь нет.\n IF p_prepared ? 'access_label_transition' THEN\n  access_label_transition:=p_prepared->'access_label_transition';\n  IF descriptor->>'command' IS DISTINCT FROM 'role.delete'\n   OR jsonb_typeof(access_label_transition) IS DISTINCT FROM 'object'\n   OR access_label_transition->>'role_id' IS DISTINCT FROM descriptor->>'id'\n   OR access_label_transition->'old_row' IS DISTINCT FROM p_sources#>'{primary,row}'\n   OR access_label_transition->'old_xmin' IS DISTINCT FROM p_sources#>'{primary,xmin}'\n   OR access_label_transition->'old_ctid' IS DISTINCT FROM p_sources#>'{primary,ctid}'\n   OR access_label_transition->>'old_digest' IS DISTINCT FROM\n    encode(sha256(convert_to((p_sources#>'{primary,row}')::text,'UTF8')),'hex')\n   OR access_label_transition->'new_row' IS DISTINCT FROM 'null'::jsonb\n   OR access_label_transition->'new_digest' IS DISTINCT FROM 'null'::jsonb\n   OR access_label_transition->'new_projection' IS DISTINCT FROM '[]'::jsonb\n   OR jsonb_typeof(access_label_transition->'old_projection') IS DISTINCT FROM 'array' THEN\n   RAISE EXCEPTION 'role delete access label prepared image differs' USING ERRCODE='42501';END IF;\n  IF jsonb_array_length(access_label_transition->'old_projection') NOT BETWEEN 1 AND 16384 THEN\n   RAISE EXCEPTION 'role delete access label prepared projection bound' USING ERRCODE='42501';END IF;\n  access_label_frozen:=jsonb_build_object('access_label_transition',access_label_transition);\n END IF;\n program:=kaname._authority_crud_command_plan_v3(p_intent,p_sources);",
    " program:=kaname._authority_crud_command_plan_v3(p_intent,p_sources);"
  ],
  [
    "DECLARE descriptor jsonb;program jsonb;domain_images jsonb;graph_index jsonb;physical jsonb;packed jsonb;\n access_label_transition jsonb;access_label_frozen jsonb:='{}';",
    "DECLARE descriptor jsonb;program jsonb;domain_images jsonb;graph_index jsonb;physical jsonb;packed jsonb;"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_resource_crud_prepare_v3(jsonb,integer,integer)',
            '8375a33475fa65f764f3b8a522185290b7b165cb9bb203d3260c3d9d887a2074',
            'ee22d1a0007376a262864613f3cef81893f76d70f2ceae94fe2e672273914aa4',
            $patch$[
  [
    " IF (access_label_frozen<>'{}'::jsonb AND octet_length((compiled->'prepared')::text)>67108864)\n OR used_rows>p_rows OR used_reads>p_reads OR jsonb_array_length(held_advisory)>4096 OR jsonb_array_length(held_relations)>256 THEN",
    " IF used_rows>p_rows OR used_reads>p_reads OR jsonb_array_length(held_advisory)>4096 OR jsonb_array_length(held_relations)>256 THEN"
  ],
  [
    "'prepared',jsonb_build_object('reserved',reserved->'reserved','held_legacy_keys',legacy_keys)||access_label_frozen,",
    "'prepared',jsonb_build_object('reserved',reserved->'reserved','held_legacy_keys',legacy_keys),"
  ],
  [
    " -- Точный OLD подтверждён общим after_capture и удержан root tuple wait.\n -- Private projection не добавляется в публичный RR capture/envelope.\n IF descriptor->>'command'='role.delete' THEN\n  access_label_old:=nullif(sources#>'{primary,row}','null'::jsonb);\n  IF access_label_old IS NOT NULL THEN\n   SELECT EXISTS(SELECT 1 FROM jsonb_array_elements(access_label_old->'rules') r\n    WHERE (r.value->>'module'='iam' AND r.value->'resources' ? 'accessLabel')\n     OR EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(r.value->'children')='array'\n       THEN r.value->'children' ELSE '[]'::jsonb END) c\n      WHERE coalesce(nullif(c.value->>'module',''),r.value->>'module')='iam'\n       AND c.value->'resources' ? 'accessLabel')) INTO access_label_needed;\n   IF NOT access_label_needed THEN\n    IF used_reads>=p_reads THEN RAISE EXCEPTION 'role delete access label probe budget' USING ERRCODE='54000';END IF;\n    SELECT EXISTS(SELECT 1 FROM kaname.authority_role_access_label_rule a\n     WHERE a.role_id=descriptor->>'id') INTO access_label_needed;\n    used_reads:=used_reads+1;\n    IF access_label_needed THEN used_rows:=used_rows+1;END IF;\n   END IF;\n   IF access_label_needed THEN\n    access_label_transition:=kaname.authority_access_label_role_transition_prepare_v1(\n     access_label_old,NULL,p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(access_label_transition->>'rows')::integer;\n    used_reads:=used_reads+(access_label_transition->>'reads')::integer;\n    IF access_label_transition->'old_xmin' IS DISTINCT FROM sources#>'{primary,xmin}'\n     OR access_label_transition->'old_ctid' IS DISTINCT FROM sources#>'{primary,ctid}' THEN\n     RAISE EXCEPTION 'role delete access label OLD version changed' USING ERRCODE='P1034';END IF;\n    held_relations:=held_relations||jsonb_build_array(jsonb_build_object(\n     'oid','kaname.authority_role_access_label_rule'::regclass::oid,'mode','RowExclusiveLock'));\n    IF access_label_transition->'old_projection'<>'[]'::jsonb THEN\n     held_relations:=held_relations||jsonb_build_array(jsonb_build_object(\n      'oid','kaname.authority_access_label_definition'::regclass::oid,'mode','RowShareLock'));\n     access_label_frozen:=jsonb_build_object('access_label_transition',access_label_transition);\n    END IF;\n   END IF;\n  END IF;\n END IF;\n certificate:=jsonb_build_object('intent',intent,'command',descriptor->>'command','program',program,'graph_index',maximum->'graph_index');",
    " certificate:=jsonb_build_object('intent',intent,'command',descriptor->>'command','program',program,'graph_index',maximum->'graph_index');"
  ],
  [
    " key_value text;table_name text;tuple_rows jsonb;used_rows integer:=0;used_reads integer:=0;compiled jsonb;preview jsonb;\n access_label_old jsonb;access_label_transition jsonb;access_label_frozen jsonb:='{}';access_label_needed boolean;",
    " key_value text;table_name text;tuple_rows jsonb;used_rows integer:=0;used_reads integer:=0;compiled jsonb;preview jsonb;"
  ]
]$patch$::jsonb
        ),
        (
            'authority_role_access_label_rule_closed_v1()',
            '9215a52e70f6989a1aa6ebc8f4d5cdc05cc78799c49688eb641eb475ac5dce67',
            '6734da847536b6e50a1b2806498ff25311e481b03f8430f1ee792e533633ce7e',
            $patch$[
  [
    "\nDECLARE program jsonb;\nBEGIN\n    IF TG_TABLE_SCHEMA='kaname' AND TG_TABLE_NAME='authority_role_access_label_rule'\n       AND TG_LEVEL='STATEMENT' AND TG_WHEN='BEFORE' AND TG_OP IN ('INSERT','DELETE')\n       AND pg_trigger_depth()>1 AND to_regclass('pg_temp.kaname_authority_sequence_program') IS NOT NULL THEN\n        PERFORM kaname.authority_protocol_require_owner();\n        program:=kaname._authority_sequence_header_v3();\n        IF program->>'family'='role' AND jsonb_typeof(program->'selected')='array'\n           AND program#>>'{frozen,mode}'='access_label_projection_write' THEN\n            RETURN NULL;\n        END IF;\n    END IF;\n    RAISE EXCEPTION 'access label role projection requires a protected writer' USING ERRCODE='42501';\nEND;\n",
    "\nBEGIN\n    RAISE EXCEPTION 'access label role projection requires a protected writer'\n        USING ERRCODE = '42501';\nEND;\n"
  ]
]$patch$::jsonb
        )
    ) AS changes(signature, before_sha, after_sha, substitutions) LOOP
        fn := pg_catalog.to_regprocedure('kaname.' || item.signature);
        IF fn IS NULL THEN RAISE EXCEPTION 'функция % для миграции отсутствует', item.signature USING ERRCODE='55000';END IF;
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
$access_label_projection_patch$;
-- +goose StatementEnd

DROP FUNCTION kaname.authority_access_label_role_projection_apply_v1(jsonb,text,text);
