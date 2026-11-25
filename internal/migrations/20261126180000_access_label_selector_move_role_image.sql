-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Вход RR содержит полный физический образ, позиции с нуля (-1 для корня)
-- и предложенные rules. Возвращаемая строка заменяет только rules. Владелец
-- сверяет её в той же транзакции до любых побочных записей и отметок времени.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_role_image_hold_v1(
    p_role_id text, p_version text, p_expected jsonb, p_moves jsonb,
    p_proposed_rules jsonb, p_rows integer, p_reads integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $hold$
DECLARE
    physical jsonb;
    old_row jsonb;
    old_rules jsonb;
    new_rules jsonb;
    receipt jsonb;
    move_count integer;
    applied integer;
    used_rows integer:=2; -- форма таблицы и строка роли
    used_reads constant integer:=3; -- форма, строка, вывод правил
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF current_setting('transaction_isolation') IS DISTINCT FROM 'read committed' THEN
        RAISE EXCEPTION 'selector move role hold requires READ COMMITTED' USING ERRCODE='25001';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN
        RAISE EXCEPTION 'selector move role image budget exhausted' USING ERRCODE='54000';
    END IF;
    IF coalesce(p_role_id,'')='' OR octet_length(p_role_id)>16384 OR p_role_id ~ '[:#*[:space:][:cntrl:]]'
        OR coalesce(p_version,'') !~ '^[0-9]{1,10}$' OR jsonb_typeof(p_expected) IS DISTINCT FROM 'array'
        OR jsonb_typeof(p_moves) IS DISTINCT FROM 'array'
        OR jsonb_typeof(p_proposed_rules) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'invalid selector move role inputs' USING ERRCODE='42501';
    END IF;
    IF octet_length(p_expected::text)::bigint + octet_length(p_moves::text)
        + octet_length(p_proposed_rules::text)>8388608 THEN
        RAISE EXCEPTION 'selector move role input exceeds byte budget' USING ERRCODE='54000';
    END IF;
    move_count:=jsonb_array_length(p_moves);
    IF jsonb_array_length(p_expected)<>3 OR move_count NOT BETWEEN 1 AND 64*17 THEN
        RAISE EXCEPTION 'invalid selector move role image or position count' USING ERRCODE='42501';
    END IF;
    used_rows:=used_rows+move_count;
    IF used_rows>p_rows THEN
        RAISE EXCEPTION 'selector move position budget exhausted' USING ERRCODE='54000';
    END IF;
    -- jsonb_to_recordset сам приводит строки и дроби к SQL-типам. Принимаем
    -- только два явно заданных целых поля в пределах структуры правила.
    IF EXISTS (SELECT FROM jsonb_array_elements(p_moves) m
        WHERE CASE WHEN jsonb_typeof(m)='object' THEN
            m-ARRAY['rule_index','child_index']<>'{}'::jsonb
            OR jsonb_typeof(m->'rule_index') IS DISTINCT FROM 'number'
            OR jsonb_typeof(m->'child_index') IS DISTINCT FROM 'number'
            OR (m->>'rule_index') !~ '^(0|[1-9][0-9]?)$'
            OR (m->>'child_index') !~ '^(-1|0|[1-9][0-9]?)$'
        ELSE true END) THEN
        RAISE EXCEPTION 'invalid selector move ordinal' USING ERRCODE='42501';
    END IF;

    -- Это удержание совместимо с обычными writers других ролей, но запрещает
    -- добавить наследника между проверкой формы и использованием образа.
    LOCK TABLE ONLY kaname.roles IN SHARE UPDATE EXCLUSIVE MODE NOWAIT;
    IF NOT EXISTS (SELECT FROM pg_class c WHERE c.oid='kaname.roles'::regclass
        AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relispartition
        AND NOT c.relhasrules AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
        AND EXISTS (SELECT FROM pg_index idx JOIN pg_attribute id
            ON id.attrelid=c.oid AND id.attname='id' AND NOT id.attisdropped
            WHERE idx.indrelid=c.oid AND idx.indisprimary AND idx.indisvalid AND idx.indisready
                AND idx.indimmediate AND idx.indnkeyatts=1 AND idx.indkey[0]=id.attnum)
        AND NOT EXISTS (SELECT FROM pg_inherits i WHERE i.inhparent=c.oid OR i.inhrelid=c.oid)) THEN
        RAISE EXCEPTION 'selector move role table shape differs' USING ERRCODE='42501';
    END IF;
    SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r)) INTO physical
        FROM ONLY kaname.roles r WHERE r.id=p_role_id FOR UPDATE OF r NOWAIT;
    IF physical IS NULL OR physical IS DISTINCT FROM p_expected OR physical->>0 IS DISTINCT FROM p_version THEN
        RAISE EXCEPTION 'selector move physical role changed' USING ERRCODE='40001';
    END IF;
    old_row:=physical->2;
    IF old_row->'live' IS DISTINCT FROM 'true'::jsonb OR old_row->'retired_at' IS DISTINCT FROM 'null'::jsonb
        OR old_row->'is_system' IS DISTINCT FROM 'false'::jsonb OR old_row->'owner_module' IS DISTINCT FROM 'null'::jsonb
        OR old_row->'cluster_id' IS DISTINCT FROM 'null'::jsonb
        OR NOT (old_row ?& ARRAY['project_id','account_id'])
        OR num_nonnulls(old_row->>'account_id',old_row->>'project_id')<>1
        OR coalesce(old_row->>'account_id',old_row->>'project_id','')=''
        OR coalesce(old_row->>'account_id',old_row->>'project_id') ~ '[:#*[:space:][:cntrl:]]' THEN
        RAISE EXCEPTION 'selector move requires a live tenant role' USING ERRCODE='42501';
    END IF;
    old_rules:=old_row->'rules';
    IF jsonb_typeof(old_rules) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'invalid selector move stored rules' USING ERRCODE='42501';
    END IF;
    IF jsonb_array_length(old_rules) NOT BETWEEN 1 AND 64 THEN
        RAISE EXCEPTION 'invalid selector move root count' USING ERRCODE='42501';
    END IF;
    used_rows:=used_rows+jsonb_array_length(old_rules);
    IF used_rows>p_rows THEN
        RAISE EXCEPTION 'selector move root budget exhausted' USING ERRCODE='54000';
    END IF;
    -- Ограничиваем число детей до разворачивания массивов.
    SELECT used_rows+sum(CASE WHEN NOT (r ? 'children') THEN 0
        WHEN jsonb_typeof(r->'children')='array' THEN jsonb_array_length(r->'children')
        ELSE 0 END) INTO used_rows FROM jsonb_array_elements(old_rules) r;
    IF used_rows>p_rows THEN
        RAISE EXCEPTION 'selector move child budget exhausted' USING ERRCODE='54000';
    END IF;
    IF kaname.iam_rules_valid(old_rules) IS DISTINCT FROM true
        OR kaname.access_label_rules_valid_v1(old_rules) IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'invalid selector move stored rules' USING ERRCODE='42501';
    END IF;

    WITH selected AS (
        SELECT DISTINCT rule_index,child_index FROM jsonb_to_recordset(p_moves) m(rule_index integer,child_index integer)
    ), roots AS (
        SELECT ordinality-1 AS rule_index,value FROM jsonb_array_elements(old_rules) WITH ORDINALITY
    ), nodes AS (
        SELECT r.rule_index,-1::bigint AS child_index,r.value FROM roots r
        UNION ALL
        SELECT r.rule_index,c.ordinality-1,c.value FROM roots r
        CROSS JOIN LATERAL jsonb_array_elements(r.value->'children') WITH ORDINALITY c
    ), marked AS (
        SELECT n.*,s.rule_index IS NOT NULL
            AND jsonb_typeof(n.value->'match_labels')='object' AND n.value->'match_labels'<>'{}'::jsonb
            AND coalesce(nullif(n.value->'match_access_labels','null'::jsonb),'{}'::jsonb)='{}'::jsonb
            AND coalesce(nullif(n.value->'resource_names','null'::jsonb),'[]'::jsonb)='[]'::jsonb
            AND coalesce(nullif(n.value->'created_by_subject','null'::jsonb),'false'::jsonb)='false'::jsonb AS moved
        FROM nodes n LEFT JOIN selected s USING (rule_index,child_index)
    ), images AS (
        SELECT rule_index,child_index,moved,CASE WHEN moved THEN
            value-ARRAY['match_labels','resource_names','created_by_subject']
                ||jsonb_build_object('match_access_labels',value->'match_labels')
            ELSE value END AS image FROM marked
    ), child_images AS (
        SELECT rule_index,jsonb_agg(image ORDER BY child_index) AS children,
            count(*) FILTER (WHERE moved) AS moved_count
        FROM images WHERE child_index>=0 GROUP BY rule_index
    )
    SELECT jsonb_agg(CASE WHEN c.moved_count>0 THEN jsonb_set(r.image,'{children}',c.children,false)
               ELSE r.image END ORDER BY r.rule_index),
           count(*) FILTER (WHERE r.moved)+coalesce(sum(c.moved_count),0)
        INTO new_rules,applied
        FROM images r LEFT JOIN child_images c USING (rule_index) WHERE r.child_index=-1;
    IF applied<>move_count OR new_rules IS DISTINCT FROM p_proposed_rules
        OR kaname.access_label_rules_valid_v1(new_rules) IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selector move positions or proposed role differ' USING ERRCODE='42501';
    END IF;
    receipt:=jsonb_build_object('physical',physical,'new_role',jsonb_set(old_row,'{rules}',new_rules,false),
        'rows',used_rows,'reads',used_reads);
    IF octet_length(receipt::text)>8388608 THEN
        RAISE EXCEPTION 'selector move role receipt exceeds byte budget' USING ERRCODE='54000';
    END IF;
    RETURN receipt;
END;
$hold$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE
    signature constant regprocedure:='kaname._authority_role_move_role_image_hold_v1(text,text,jsonb,jsonb,jsonb,integer,integer)'::regprocedure;
    grantee record;
BEGIN
    FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
        CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
        WHERE p.oid=signature AND a.grantee<>p.proowner
    LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',signature,
            CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_role_move_role_image_hold_v1(text,text,jsonb,jsonb,jsonb,integer,integer);
