-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Владелец удерживает физический источник каждой вложенной копии и
-- повторно сверяет допустимые пары на финальных часах решения.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Выводит все основания из OLD-роли, удержанного графа и всех её выдач.
-- Граф и держателей передаёт только закрытый этап подготовки владельца.
CREATE FUNCTION kaname._authority_role_move_project_copy_support_v1(
    p_graph_receipt jsonb,p_role jsonb,p_moves jsonb,p_definition boolean,p_holders jsonb,p_rows integer
) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $support$
DECLARE
    graph jsonb:=p_graph_receipt->'graph';
    project_id text:=p_graph_receipt->>'project_id';
    mirror_accounts jsonb:=graph->'current_accounts';
    mirror_project text:=graph->>'current_project';
    ancestors jsonb[];
    ancestor jsonb;
    ancestor_id text;
    holders jsonb:=p_holders;
    holder record;
    scope jsonb;
    target jsonb;
    resources jsonb;
    holder_mask integer;
    source_masks jsonb[]:=ARRAY[]::jsonb[];
    source jsonb;
    move jsonb;
    owner_rule jsonb;
    child_rule jsonb;
    child_pairs jsonb;
    matched jsonb;
    move_mask integer;
    item jsonb;
    positions jsonb[]:=ARRAY[]::jsonb[];
    rule_index integer;
    child_index integer;
    i integer;
    used_rows bigint;
    matcher_rows bigint;
    ancestor_label_rows bigint:=0;
    child_pair_rows integer;
    output_bytes bigint:=2;
    forbidden constant text:=U&'[:#*\0001-\0020\007F-\00A0\1680\2000-\200A\2028\2029\202F\205F\3000]';
BEGIN
    IF graph->'present' IS DISTINCT FROM 'true'::jsonb
        OR graph#>>'{projection,object_id}' IS DISTINCT FROM project_id
        OR coalesce(project_id,'')=''
        OR jsonb_typeof(graph->'ancestors') IS DISTINCT FROM 'array'
        OR jsonb_typeof(mirror_accounts) IS DISTINCT FROM 'array'
        OR jsonb_typeof(p_role->'rules') IS DISTINCT FROM 'array'
        OR p_role->'live' IS DISTINCT FROM 'true'::jsonb
        OR jsonb_typeof(p_moves) IS DISTINCT FROM 'array'
        OR p_definition IS NULL
        OR jsonb_typeof(p_holders) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'project copy support requires the held role and graph' USING ERRCODE='42501';
    END IF;
    IF jsonb_array_length(graph->'ancestors') NOT BETWEEN 1 AND 4
        OR jsonb_array_length(mirror_accounts)>1
        OR jsonb_array_length(p_moves) NOT BETWEEN 1 AND 1088 THEN
        RAISE EXCEPTION 'project copy support has no bounded candidate positions' USING ERRCODE='42501';
    END IF;
    used_rows:=1+jsonb_array_length(p_moves)+jsonb_array_length(graph->'ancestors');
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000 THEN
        RAISE EXCEPTION 'project copy support exceeds budget' USING ERRCODE='54000';
    END IF;

    SELECT array_agg(value ORDER BY ordinality) INTO ancestors
      FROM jsonb_array_elements(graph->'ancestors') WITH ORDINALITY;
    FOREACH ancestor IN ARRAY ancestors LOOP
        IF ancestor->'object_type' IS DISTINCT FROM '"iam.account"'::jsonb
            OR ancestor#>'{projection,id}' IS DISTINCT FROM ancestor->'object_id'
            OR jsonb_typeof(ancestor->'object_id') IS DISTINCT FROM 'string'
            OR jsonb_typeof(ancestor#>'{projection,labels}') IS DISTINCT FROM 'object'
            OR ancestor->'present' IS DISTINCT FROM 'true'::jsonb THEN
            RAISE EXCEPTION 'invalid held ancestor for project copy support' USING ERRCODE='42501';
        END IF;
        ancestor_label_rows:=ancestor_label_rows+
            (SELECT count(*) FROM jsonb_object_keys(ancestor#>'{projection,labels}'));
    END LOOP;
    IF jsonb_typeof(graph#>'{projection,labels}') IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'invalid held project mirror labels' USING ERRCODE='42501';
    END IF;
    matcher_rows:=ancestor_label_rows+cardinality(ancestors)*
        (1+(SELECT count(*) FROM jsonb_object_keys(graph#>'{projection,labels}')));
    used_rows:=used_rows+matcher_rows;
    IF used_rows>p_rows THEN
        RAISE EXCEPTION 'project copy graph labels exceed budget' USING ERRCODE='54000';
    END IF;

    -- Если последний подходящий держатель истёк после RR, область определения
    -- потребует нового снимка. Определение допустимо только в исходном режиме.
    IF p_definition IS DISTINCT FROM (p_holders='{}'::jsonb) THEN
        RAISE EXCEPTION 'project copy source mode changed since capture' USING ERRCODE='40001';
    END IF;
    IF p_definition THEN
        IF p_role->'is_system' IS DISTINCT FROM 'false'::jsonb
            OR coalesce(p_role->>'cluster_id','')<>''
            OR coalesce(p_role->>'owner_module','')<>''
            OR (coalesce(p_role->>'account_id','')='')=(coalesce(p_role->>'project_id','')='') THEN
            RAISE EXCEPTION 'invalid held project copy definition' USING ERRCODE='42501';
        END IF;
        scope:=CASE WHEN coalesce(p_role->>'account_id','')<>''
            THEN jsonb_build_array('account',p_role->>'account_id')
            ELSE jsonb_build_array('project',p_role->>'project_id') END;
        holders:=jsonb_build_object('',jsonb_build_object(
            'scope',scope,'target',jsonb_build_object('allInScope',true)));
    END IF;

    -- Маска на четыре возможных ребра сохраняет различие между реальным
    -- контейнером и отчётной областью зеркала. Цель проверяется на контейнере.
    used_rows:=used_rows+(SELECT count(*) FROM (
        SELECT key FROM jsonb_object_keys(holders) key LIMIT p_rows-used_rows+1
    ) bounded);
    IF used_rows>p_rows THEN
        RAISE EXCEPTION 'project copy holder scan exceeds budget' USING ERRCODE='54000';
    END IF;
    FOR holder IN SELECT key AS id,value FROM jsonb_each(holders) ORDER BY key COLLATE "C"
    LOOP
        scope:=holder.value->'scope';
        target:=holder.value->'target';
        resources:=coalesce(target->'resources','[]'::jsonb);
        IF jsonb_typeof(scope) IS DISTINCT FROM 'array'
            OR jsonb_typeof(scope->0) IS DISTINCT FROM 'string'
            OR jsonb_typeof(scope->1) IS DISTINCT FROM 'string'
            OR octet_length(scope->>1) NOT BETWEEN 1 AND 16384
            OR (scope->>1) COLLATE "C" ~ forbidden
            OR scope->>0 NOT IN ('cluster','account','project')
            OR (scope->>0='cluster' AND scope->>1<>'cluster_root')
            OR (NOT p_definition AND coalesce(holder.value->>'class','') NOT IN ('ACTIVE','PENDING'))
            OR jsonb_typeof(target) IS DISTINCT FROM 'object'
            OR target-ARRAY['allInScope','resources']<>'{}'::jsonb
            OR jsonb_typeof(resources) IS DISTINCT FROM 'array'
            OR (target ? 'allInScope' AND jsonb_typeof(target->'allInScope') IS DISTINCT FROM 'boolean') THEN
            RAISE EXCEPTION 'invalid held project copy holder scope or target' USING ERRCODE='42501';
        END IF;
        IF jsonb_array_length(scope)<>2 OR jsonb_array_length(resources)>256
            OR (resources<>'[]'::jsonb AND target->'allInScope'='true'::jsonb) THEN
            RAISE EXCEPTION 'invalid held project copy holder bounds' USING ERRCODE='42501';
        END IF;
        used_rows:=used_rows+jsonb_array_length(resources);
        IF used_rows>p_rows THEN
            RAISE EXCEPTION 'project copy holder targets exceed budget' USING ERRCODE='54000';
        END IF;
        IF EXISTS(SELECT FROM jsonb_array_elements(resources) ref
            WHERE jsonb_typeof(ref) IS DISTINCT FROM 'object'
                OR jsonb_typeof(ref->'type') IS DISTINCT FROM 'string'
                OR jsonb_typeof(ref->'id') IS DISTINCT FROM 'string'
                OR octet_length(ref->>'type') NOT BETWEEN 1 AND 16384
                OR octet_length(ref->>'id') NOT BETWEEN 1 AND 16384
                OR (ref->>'id') COLLATE "C" ~ forbidden) THEN
            RAISE EXCEPTION 'invalid held project copy finite target' USING ERRCODE='42501';
        END IF;
        IF NOT kaname._authority_resource_contained_v2(scope->>0,scope->>1,mirror_accounts,mirror_project)
            OR scope->>0='project' THEN
            CONTINUE;
        END IF;
        used_rows:=used_rows+cardinality(ancestors)*(1+jsonb_array_length(resources));
        IF used_rows>p_rows THEN
            RAISE EXCEPTION 'project copy holder targets exceed budget' USING ERRCODE='54000';
        END IF;
        holder_mask:=0;
        FOR i IN 1..cardinality(ancestors) LOOP
            ancestor_id:=ancestors[i]->>'object_id';
            IF kaname._authority_resource_contained_v2(scope->>0,scope->>1,jsonb_build_array(ancestor_id),'')
                AND kaname._authority_resource_target_contains_v2(target,'iam.account',ancestor_id) THEN
                holder_mask:=holder_mask | (1 << (i-1));
            END IF;
        END LOOP;
        IF holder_mask<>0 THEN
            source_masks:=array_append(source_masks,jsonb_build_object('id',holder.id,'mask',holder_mask));
        END IF;
    END LOOP;

    -- Сопоставляем полное OLD-условие с каждым предком один раз на позицию.
    -- Область и конечная цель конкретного держателя уже учтены в его маске.
    FOR move IN SELECT value FROM jsonb_array_elements(p_moves)
    LOOP
        rule_index:=(move->>'rule_index')::integer;
        child_index:=(move->>'child_index')::integer;
        IF rule_index IS NULL OR rule_index NOT BETWEEN 0 AND 63
            OR child_index IS NULL OR child_index NOT BETWEEN -1 AND 15 THEN
            RAISE EXCEPTION 'invalid held project move indices' USING ERRCODE='42501';
        END IF;
        IF child_index=-1 THEN CONTINUE;END IF;
        owner_rule:=p_role->'rules'->rule_index;
        child_rule:=owner_rule->'children'->child_index;
        IF owner_rule->'module' IS DISTINCT FROM '"iam"'::jsonb
            OR owner_rule->'resources' IS DISTINCT FROM '["account"]'::jsonb
            OR (child_rule->'resources' ? 'project') IS DISTINCT FROM true THEN
            CONTINUE;
        END IF;
        child_pairs:=child_rule->'match_labels';
        IF jsonb_typeof(child_pairs) IS DISTINCT FROM 'object' OR child_pairs='{}'::jsonb THEN
            RAISE EXCEPTION 'project copy support lacks the OLD child labels' USING ERRCODE='42501';
        END IF;
        child_pair_rows:=(SELECT count(*) FROM jsonb_object_keys(child_pairs));
        used_rows:=used_rows+child_pair_rows;
        IF used_rows>p_rows THEN
            RAISE EXCEPTION 'project copy predicates exceed budget' USING ERRCODE='54000';
        END IF;
        IF kaname.access_labels_valid_v1(child_pairs) IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'invalid held project child labels' USING ERRCODE='42501';
        END IF;
        IF (graph#>'{projection,labels}' @> child_pairs) IS DISTINCT FROM true THEN CONTINUE;END IF;

        used_rows:=used_rows+matcher_rows+cardinality(ancestors)*child_pair_rows;
        IF used_rows>p_rows THEN
            RAISE EXCEPTION 'project copy predicates exceed budget' USING ERRCODE='54000';
        END IF;
        move_mask:=0;
        FOR i IN 1..cardinality(ancestors) LOOP
            matched:=kaname._authority_role_move_old_project_match_v1(p_role->'rules',rule_index,child_index,
                '["cluster","cluster_root"]'::jsonb,'{"allInScope":true}'::jsonb,
                ancestors[i]->'projection',graph->'projection',project_id,mirror_accounts->>0);
            IF matched IS NOT NULL THEN move_mask:=move_mask | (1 << (i-1)); END IF;
        END LOOP;
        IF move_mask=0 THEN CONTINUE;END IF;
        used_rows:=used_rows+cardinality(source_masks);
        IF used_rows>p_rows THEN
            RAISE EXCEPTION 'project copy support combinations exceed budget' USING ERRCODE='54000';
        END IF;
        FOREACH source IN ARRAY source_masks LOOP
            IF (move_mask & (source->>'mask')::integer)=0 THEN CONTINUE;END IF;
            item:=jsonb_build_object('rule_index',rule_index,'child_index',child_index,'pairs',child_pairs);
            IF NOT p_definition THEN item:=item||jsonb_build_object('binding_id',source->'id');END IF;
            output_bytes:=output_bytes+octet_length(item::text)+2;
            IF output_bytes>8388608 THEN
                RAISE EXCEPTION 'project copy support receipt exceeds byte budget' USING ERRCODE='54000';
            END IF;
            positions:=array_append(positions,item);
        END LOOP;
    END LOOP;
    IF p_definition AND cardinality(positions)>0
        AND p_graph_receipt#>>'{native,2,account_id}' IS DISTINCT FROM p_role->>'account_id' THEN
        RAISE EXCEPTION 'native project is outside the role definition scope' USING ERRCODE='42501';
    END IF;
    RETURN jsonb_build_object('positions',to_jsonb(positions),'rows',used_rows);
END;
$support$;

-- Истёкшая выдача может убрать лишь свою поддержку. Отдельно удержанная
-- область определения обозначается позицией без привязки.
CREATE FUNCTION kaname._authority_role_move_project_copy_pairs_v1(
    p_source jsonb,p_holders jsonb,p_rows integer
) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $pairs$
DECLARE
    item jsonb;
    pairs jsonb[];
    matched jsonb;
    used_rows integer;
BEGIN
    IF jsonb_typeof(p_source->'positions') IS DISTINCT FROM 'array'
        OR jsonb_typeof(p_holders) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'invalid held project copy support' USING ERRCODE='42501';
    END IF;
    used_rows:=jsonb_array_length(p_source->'positions');
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000 THEN
        RAISE EXCEPTION 'held project copy pairs exceed budget' USING ERRCODE='54000';
    END IF;
    pairs:=ARRAY[]::jsonb[];
    FOR item IN SELECT value FROM jsonb_array_elements(p_source->'positions')
    LOOP
        matched:=item->'pairs';
        IF kaname.access_labels_valid_v1(matched) IS DISTINCT FROM true OR matched='{}'::jsonb THEN
            RAISE EXCEPTION 'invalid held OLD project copy pairs' USING ERRCODE='42501';
        END IF;
        used_rows:=used_rows+(SELECT count(*) FROM jsonb_object_keys(matched));
        IF used_rows>p_rows THEN
            RAISE EXCEPTION 'held project copy pairs exceed budget' USING ERRCODE='54000';
        END IF;
        IF NOT (item ? 'binding_id') THEN
            IF p_holders<>'{}'::jsonb THEN
                RAISE EXCEPTION 'held project definition support differs from final holder mode' USING ERRCODE='40001';
            END IF;
            pairs:=array_append(pairs,matched);
        ELSIF p_holders->(item->>'binding_id')->>'class' IN ('ACTIVE','PENDING') THEN
            pairs:=array_append(pairs,matched);
        END IF;
    END LOOP;
    WITH selected AS MATERIALIZED (
        SELECT DISTINCT kv.key,kv.value FROM unnest(pairs) m CROSS JOIN LATERAL jsonb_each(m) kv
    )
    SELECT CASE WHEN count(*)=count(DISTINCT key)
        THEN coalesce(jsonb_object_agg(key,value),'{}'::jsonb) END INTO matched FROM selected;
    IF matched IS NULL THEN
        RAISE EXCEPTION 'held old project copy sources disagree' USING ERRCODE='40001';
    END IF;
    RETURN jsonb_build_object('pairs',matched,'rows',used_rows);
END;
$pairs$;

-- Заменяет предложение Go квитанцией, выведенной владельцем из удержанных строк.
CREATE FUNCTION kaname._authority_role_move_project_copy_plan_hold_v1(
    p_plan jsonb,p_role jsonb,p_moves jsonb,p_holders jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $project_plan$
DECLARE
    item jsonb;
    proposed jsonb;
    capture jsonb;
    support jsonb;
    pairs jsonb;
    result jsonb[]:=ARRAY[]::jsonb[];
    used_rows integer;
    used_reads integer:=1;
    bytes bigint:=2;
BEGIN
    PERFORM kaname._authority_role_move_attestation_v1();
    IF jsonb_typeof(p_plan) IS DISTINCT FROM 'array' OR octet_length(p_plan::text)>8388608 THEN
        RAISE EXCEPTION 'invalid project copy plan' USING ERRCODE='42501';
    END IF;
    used_rows:=jsonb_array_length(p_plan);
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN
        RAISE EXCEPTION 'project copy plan exceeds budget' USING ERRCODE='54000';
    END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(p_plan)
        ORDER BY (value->>'root_type') COLLATE "C",(value->>'root_id') COLLATE "C"
    LOOP
        IF item ? 'project_source' THEN
            proposed:=item->'project_source';
            IF item->>'root_type' IS DISTINCT FROM 'iam.project'
                OR jsonb_typeof(proposed) IS DISTINCT FROM 'object'
                OR proposed-ARRAY['mirror_physical','definition']<>'{}'::jsonb
                OR jsonb_typeof(proposed->'definition') IS DISTINCT FROM 'boolean' THEN
                RAISE EXCEPTION 'invalid proposed project copy source' USING ERRCODE='42501';
            END IF;
            capture:=kaname._authority_role_move_project_copy_graph_hold_v1(item->>'root_id',item->'physical',
                proposed->'mirror_physical',p_rows-used_rows,p_reads-used_reads);
            used_rows:=used_rows+(capture->>'rows')::integer;
            used_reads:=used_reads+(capture->>'reads')::integer;
            support:=kaname._authority_role_move_project_copy_support_v1(capture,p_role,p_moves,
                (proposed->>'definition')::boolean,p_holders,p_rows-used_rows);
            used_rows:=used_rows+(support->>'rows')::integer;
            IF support->'positions'='[]'::jsonb THEN
                RAISE EXCEPTION 'held project does not match the whole OLD child selector' USING ERRCODE='40001';
            END IF;
            proposed:=jsonb_build_object('graph',capture-ARRAY['rows','reads'],'positions',support->'positions');
            pairs:=kaname._authority_role_move_project_copy_pairs_v1(proposed,p_holders,p_rows-used_rows);
            used_rows:=used_rows+(pairs->>'rows')::integer;
            IF EXISTS(SELECT FROM jsonb_each(pairs->'pairs') a
                WHERE NOT (capture#>'{native,2,access_labels}' ? a.key)
                    AND item->'new_access_labels'->a.key IS DISTINCT FROM a.value) THEN
                RAISE EXCEPTION 'prepared copy omits part of the held OLD project selector' USING ERRCODE='40001';
            END IF;
            item:=jsonb_set(item,'{project_source}',proposed||jsonb_build_object('pairs',pairs->'pairs'));
        END IF;
        bytes:=bytes+octet_length(item::text)+2;
        IF bytes>8388608 THEN
            RAISE EXCEPTION 'held project copy plan exceeds byte budget' USING ERRCODE='54000';
        END IF;
        result:=array_append(result,item);
    END LOOP;
    RETURN jsonb_build_object('plan',to_jsonb(result),'rows',used_rows,'reads',used_reads);
END;
$project_plan$;

-- Перед командой записи сравнивает физический граф и подтверждает полную
-- карту ненативных пар после исключения истёкших держателей.
CREATE FUNCTION kaname._authority_role_move_project_copy_plan_require_v1(
    p_plan jsonb,p_copies jsonb,p_holders jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $project_plan$
DECLARE
    root record;
    source jsonb;
    graph jsonb;
    mirror jsonb;
    actual_graph jsonb;
    pairs jsonb;
    final_by_project jsonb;
    old_access jsonb;
    native_labels jsonb;
    final_access jsonb;
    expected_pairs jsonb;
    proposed_pairs jsonb;
    used_rows integer;
    used_reads integer:=1;
BEGIN
    PERFORM kaname._authority_role_move_attestation_v1();
    IF jsonb_typeof(p_plan) IS DISTINCT FROM 'object'
        OR jsonb_typeof(p_copies) IS DISTINCT FROM 'array'
        OR jsonb_typeof(p_holders) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'invalid held project copy decision' USING ERRCODE='42501';
    END IF;
    used_rows:=jsonb_array_length(p_copies);
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN
        RAISE EXCEPTION 'project copy decision exceeds budget' USING ERRCODE='54000';
    END IF;
    SELECT coalesce(jsonb_object_agg(value->>'root_id',value->'new_access_labels'),'{}'::jsonb)
      INTO final_by_project FROM jsonb_array_elements(p_copies)
     WHERE value->>'root_type'='iam.project' AND jsonb_typeof(value->'root_id')='string';

    FOR root IN SELECT key,value FROM jsonb_each(p_plan) WHERE value ? 'project_source'
        ORDER BY key COLLATE "C"
    LOOP
        source:=root.value->'project_source';
        graph:=source->'graph';
        mirror:=graph->'sources'->(jsonb_build_array(2,'iam.project',root.value->>'root_id','')::text)#>'{states,0}';
        IF root.value->>'root_type' IS DISTINCT FROM 'iam.project'
            OR root.key IS DISTINCT FROM 'iam.project:'||(root.value->>'root_id') THEN
            RAISE EXCEPTION 'held project copy decision coordinate differs' USING ERRCODE='42501';
        END IF;
        actual_graph:=kaname._authority_role_move_project_copy_graph_hold_v1(root.value->>'root_id',
            root.value->'physical',mirror,p_rows-used_rows,p_reads-used_reads);
        used_rows:=used_rows+(actual_graph->>'rows')::integer;
        used_reads:=used_reads+(actual_graph->>'reads')::integer;
        IF actual_graph-ARRAY['rows','reads'] IS DISTINCT FROM graph THEN
            RAISE EXCEPTION 'held project copy graph changed after preparation' USING ERRCODE='40001';
        END IF;
        pairs:=kaname._authority_role_move_project_copy_pairs_v1(source,p_holders,p_rows-used_rows);
        used_rows:=used_rows+(pairs->>'rows')::integer;
        old_access:=root.value#>'{physical,2,access_labels}';
        native_labels:=root.value#>'{physical,2,labels}';
        final_access:=coalesce(final_by_project->(root.value->>'root_id'),old_access);
        IF kaname.access_labels_valid_v1(final_access) IS DISTINCT FROM true
            OR NOT (final_access @> old_access) OR jsonb_typeof(native_labels) IS DISTINCT FROM 'object' THEN
            RAISE EXCEPTION 'invalid project copy decision labels' USING ERRCODE='42501';
        END IF;
        used_rows:=used_rows+(SELECT count(*) FROM jsonb_object_keys(final_access))
            +(SELECT count(*) FROM jsonb_object_keys(pairs->'pairs'));
        IF used_rows>p_rows THEN
            RAISE EXCEPTION 'project copy decision labels exceed budget' USING ERRCODE='54000';
        END IF;
        IF EXISTS(SELECT FROM jsonb_each(pairs->'pairs') a WHERE old_access ? a.key
                AND old_access->a.key IS DISTINCT FROM a.value) THEN
            RAISE EXCEPTION 'held project copy conflicts with a protected value' USING ERRCODE='40001';
        END IF;
        SELECT coalesce(jsonb_object_agg(key,value),'{}'::jsonb) INTO expected_pairs
          FROM jsonb_each(pairs->'pairs') WHERE NOT (old_access ? key)
            AND native_labels->key IS DISTINCT FROM value;
        SELECT coalesce(jsonb_object_agg(key,value),'{}'::jsonb) INTO proposed_pairs
          FROM jsonb_each(final_access) WHERE NOT (old_access ? key)
            AND native_labels->key IS DISTINCT FROM value;
        IF NOT (final_access @> (pairs->'pairs')) OR expected_pairs IS DISTINCT FROM proposed_pairs THEN
            RAISE EXCEPTION 'project copy differs from the final held selector sources' USING ERRCODE='40001';
        END IF;
    END LOOP;
    RETURN jsonb_build_object('rows',used_rows,'reads',used_reads);
END;
$project_plan$;

-- Полная перепись обратных рёбер одного аккаунта. Вызов с SQL NULL
-- удерживает источники, повторный вызов сверяет квитанцию в той же транзакции.
-- Кандидат означает только физическое ребро к проекту с зеркалом.
CREATE FUNCTION kaname._authority_role_move_project_reverse_edges_v1(
    p_scope_id text,p_expected jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $reverse$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    forbidden constant text:=U&'[:#*\0001-\0020\007F-\00A0\1680\2000-\200A\2028\2029\202F\205F\3000]';
    source jsonb;
    catalog_versions jsonb;
    account_model text;
    project_model text;
    oversized boolean;
    expected_count integer;
    cap integer;
    edges refcursor;
    edge_row record;
    mirror_version jsonb;
    image jsonb;
    images jsonb[]:=ARRAY[]::jsonb[];
    image_bytes bigint:=2;
    digest text;
    candidate_ids jsonb;
    result jsonb;
    -- Аттестация, три relation lock, custody и индексы, выборка двух типов.
    used_rows integer:=11;
    used_reads integer:=12;
BEGIN
    IF coalesce(p_scope_id,'')='' OR octet_length(p_scope_id)>16384 OR p_scope_id COLLATE "C" ~ forbidden THEN
        RAISE EXCEPTION 'invalid reverse project census account' USING ERRCODE='42501';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows+3 AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads+1 AND 4096
        OR octet_length(p_expected::text)>8388608 THEN
        RAISE EXCEPTION 'reverse project census exceeds input budget' USING ERRCODE='54000';
    END IF;
    source:=jsonb_build_object('state','held','scope_id',p_scope_id,'nonce',proof->'nonce',
        'invoker_oid',proof->'invoker_oid','catalog_id',proof->'catalog_id',
        'backend_pid',pg_backend_pid(),'txid',pg_current_xact_id()::text);
    IF p_expected IS NOT NULL THEN
        IF jsonb_typeof(p_expected) IS DISTINCT FROM 'object'
            OR jsonb_typeof(p_expected->'catalog') IS DISTINCT FROM 'array'
            OR jsonb_typeof(p_expected->'count') IS DISTINCT FROM 'number'
            OR p_expected->>'count' !~ '^(0|[1-9][0-9]{0,3})$'
            OR jsonb_typeof(p_expected->'sha256') IS DISTINCT FROM 'string'
            OR p_expected->>'sha256' !~ '^[0-9a-f]{64}$' THEN
            RAISE EXCEPTION 'invalid held reverse project census' USING ERRCODE='42501';
        END IF;
        expected_count:=(p_expected->>'count')::integer;
        IF expected_count>4096 OR jsonb_array_length(p_expected->'catalog')<>2 THEN
            RAISE EXCEPTION 'invalid held reverse project census bounds' USING ERRCODE='42501';
        END IF;
        IF p_expected-ARRAY['catalog','count','sha256'] IS DISTINCT FROM source THEN
            RAISE EXCEPTION 'reverse project census differs from held scope or transaction' USING ERRCODE='40001';
        END IF;
    ELSE
        -- Такой же порядок, как при регистрации и снятии. При повторе только
        -- проверяем замки: заново получить предикат после разрыва нельзя.
        LOCK TABLE ONLY kaname.catalog_resource, ONLY kaname.resource_mirror, ONLY kaname.resource_parent_edge
            IN SHARE MODE NOWAIT;
    END IF;
    IF EXISTS(SELECT FROM unnest(ARRAY['kaname.catalog_resource'::regclass,'kaname.resource_mirror'::regclass,
                'kaname.resource_parent_edge'::regclass]) relation(oid)
        WHERE NOT EXISTS(SELECT FROM pg_class c JOIN pg_locks l ON l.relation=c.oid WHERE c.oid=relation.oid
            AND c.relowner=current_user::regrole AND c.relkind='r' AND c.relpersistence='p'
            AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relispartition OR c.relhasrules)
            AND NOT EXISTS(SELECT FROM pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid)
            AND has_table_privilege((proof->>'invoker_oid')::oid,c.oid,'SELECT')
            AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
            AND l.pid=pg_backend_pid() AND l.granted AND l.locktype='relation' AND l.mode='ShareLock')) THEN
        RAISE EXCEPTION 'reverse project census source custody differs' USING ERRCODE='42501';
    END IF;
    IF EXISTS(SELECT FROM (VALUES
        ('kaname.catalog_resource'::regclass,'dotted','live',true),
        ('kaname.resource_mirror'::regclass,'object_type','object_id',true),
        ('kaname.resource_parent_edge'::regclass,'parent_type','parent_id',false)) key(rel,first_col,second_col,unique_key)
        WHERE NOT EXISTS(SELECT FROM pg_index ix JOIN pg_class idx ON idx.oid=ix.indexrelid
            JOIN pg_am am ON am.oid=idx.relam
            JOIN pg_attribute a ON a.attrelid=ix.indrelid AND a.attnum=ix.indkey[0]
            JOIN pg_attribute b ON b.attrelid=ix.indrelid AND b.attnum=ix.indkey[1]
            WHERE ix.indrelid=key.rel AND am.amname='btree'
                AND ix.indisvalid AND ix.indisready AND ix.indpred IS NULL AND ix.indexprs IS NULL
                AND ix.indnkeyatts=2 AND a.attname=key.first_col AND b.attname=key.second_col
                AND (NOT key.unique_key OR (ix.indisunique AND ix.indimmediate)))) THEN
        RAISE EXCEPTION 'reverse project census source keys differ' USING ERRCODE='42501';
    END IF;
    SELECT coalesce(jsonb_agg(jsonb_build_array(c.dotted,c.model,c.x,c.t) ORDER BY c.dotted COLLATE "C"),'[]'),
        max(c.model) FILTER(WHERE c.dotted='iam.account'),max(c.model) FILTER(WHERE c.dotted='iam.project'),
        bool_or(c.too_long)
      INTO catalog_versions,account_model,project_model,oversized
      FROM (SELECT c.dotted,CASE WHEN octet_length(c.object_type)<=16384 THEN c.object_type END AS model,
                octet_length(c.object_type)>16384 AS too_long,c.xmin::text x,c.ctid::text t
            FROM ONLY kaname.catalog_resource c WHERE c.live AND c.dotted IN ('iam.account','iam.project') LIMIT 3) c;
    used_rows:=used_rows+jsonb_array_length(catalog_versions);
    IF oversized THEN RAISE EXCEPTION 'reverse project catalog exceeds byte limit' USING ERRCODE='54000';END IF;
    IF p_expected IS NOT NULL AND catalog_versions IS DISTINCT FROM p_expected->'catalog' THEN
        RAISE EXCEPTION 'reverse project census catalog changed' USING ERRCODE='40001';
    END IF;
    IF jsonb_array_length(catalog_versions)<>2 OR coalesce(account_model,'')='' OR coalesce(project_model,'')=''
        OR account_model=project_model OR account_model COLLATE "C" ~ forbidden OR project_model COLLATE "C" ~ forbidden THEN
        RAISE EXCEPTION 'missing or ambiguous reverse project catalog' USING ERRCODE='42501';
    END IF;
    -- Каждое ребро оплачивает выборку, возможное зеркало и два прохода
    -- по удержанным образам. Отдельный FETCH оставлен для контрольной строки.
    cap:=least(4096,(p_rows-used_rows-1)/4,(p_reads-used_reads-1)/2);
    IF expected_count IS NOT NULL THEN
        IF cap<expected_count THEN
            RAISE EXCEPTION 'held reverse project census exceeds replay budget' USING ERRCODE='54000';
        END IF;
        cap:=expected_count;
    END IF;
    OPEN edges NO SCROLL FOR
        SELECT e.xmin::text x,e.ctid::text t,
            CASE WHEN octet_length(e.object_id)<=16384 THEN e.object_id END AS object_id,
            CASE WHEN octet_length(e.object_type)<=16384 THEN e.object_type END AS object_type
        FROM ONLY kaname.resource_parent_edge e
        WHERE e.parent_type=account_model AND e.parent_id=p_scope_id LIMIT cap+1;
    LOOP
        FETCH NEXT FROM edges INTO edge_row;
        used_reads:=used_reads+1;
        EXIT WHEN NOT FOUND;
        used_rows:=used_rows+1;
        IF cardinality(images)>=cap THEN
            IF expected_count IS NOT NULL THEN
                RAISE EXCEPTION 'held reverse project census grew' USING ERRCODE='40001';
            END IF;
            RAISE EXCEPTION 'reverse project edge census exceeds budget' USING ERRCODE='54000';
        END IF;
        IF edge_row.object_id IS NULL OR edge_row.object_type IS NULL THEN
            RAISE EXCEPTION 'reverse project edge coordinates exceed byte limit' USING ERRCODE='54000';
        END IF;
        mirror_version:=NULL;
        IF edge_row.object_type=project_model THEN
            SELECT jsonb_build_array(m.xmin::text,m.ctid::text) INTO mirror_version
              FROM ONLY kaname.resource_mirror m WHERE m.object_type='iam.project' AND m.object_id=edge_row.object_id;
            used_reads:=used_reads+1;
            used_rows:=used_rows+1;
            IF mirror_version IS NOT NULL AND (edge_row.object_id='' OR edge_row.object_id COLLATE "C" ~ forbidden) THEN
                RAISE EXCEPTION 'invalid reverse project child identity' USING ERRCODE='42501';
            END IF;
        END IF;
        image:=jsonb_build_array(edge_row.x,edge_row.t,edge_row.object_type,edge_row.object_id,mirror_version);
        image_bytes:=image_bytes+octet_length(image::text)+2;
        IF image_bytes>8388608 THEN
            RAISE EXCEPTION 'reverse project edge census exceeds byte limit' USING ERRCODE='54000';
        END IF;
        used_rows:=used_rows+2;
        images:=array_append(images,image);
    END LOOP;
    CLOSE edges;
    -- В хеш входят повторы, другие типы и отсутствующие зеркала; их нельзя
    -- отбрасывать до полного ограниченного чтения. ID упорядочиваем отдельно.
    SELECT encode(sha256(convert_to(coalesce(jsonb_agg(v ORDER BY (v->>1)::tid),'[]')::text,'UTF8')),'hex')
      INTO digest FROM unnest(images) v;
    source:=source||jsonb_build_object('catalog',catalog_versions,'count',cardinality(images),'sha256',digest);
    IF p_expected IS NOT NULL AND source IS DISTINCT FROM p_expected THEN
        RAISE EXCEPTION 'held reverse project edges or mirror generations changed' USING ERRCODE='40001';
    END IF;
    SELECT coalesce(jsonb_agg(id ORDER BY id COLLATE "C"),'[]') INTO candidate_ids
      FROM (SELECT DISTINCT (v->>3) COLLATE "C" AS id FROM unnest(images) v WHERE v->4<>'null'::jsonb) candidates;
    result:=jsonb_build_object('source',source,'candidate_ids',candidate_ids,'rows',used_rows,'reads',used_reads);
    IF octet_length(result::text)>8388608 THEN
        RAISE EXCEPTION 'reverse project census receipt exceeds byte limit' USING ERRCODE='54000';
    END IF;
    RETURN result;
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'reverse project census sources busy' USING ERRCODE='40001';
END;
$reverse$;

-- Типизированный план владельцев для всех проверенных OLD-позиций,
-- которые переносят вложенный проект. План не зависит от списка копий.
CREATE FUNCTION kaname._authority_role_move_project_moved_owner_plan_v1(
    p_role jsonb,p_moves jsonb,p_rows integer
) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $owners$
DECLARE
    move jsonb;
    owner_rule jsonb;
    names jsonb;
    ordinary jsonb;
    protected jsonb;
    predicates jsonb[]:=ARRAY[]::jsonb[];
    plan jsonb;
    used_rows integer;
    bytes bigint:=2;
BEGIN
    IF jsonb_typeof(p_role->'rules') IS DISTINCT FROM 'array'
        OR jsonb_typeof(p_moves) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'invalid project owner selector input' USING ERRCODE='42501';
    END IF;
    used_rows:=jsonb_array_length(p_moves);
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000 OR used_rows>1088 THEN
        RAISE EXCEPTION 'project owner selector input exceeds budget' USING ERRCODE='54000';
    END IF;
    FOR move IN SELECT value FROM jsonb_array_elements(p_moves) LOOP
        -- Позиции сверены с удержанной OLD при построении NEW. Отрицательный
        -- child_index означает перенос корневого селектора.
        IF move->>'child_index'='-1' THEN CONTINUE;END IF;
        owner_rule:=p_role#>ARRAY['rules',move->>'rule_index'];
        IF owner_rule->'module' IS DISTINCT FROM '"iam"'::jsonb
            OR owner_rule->'resources' IS DISTINCT FROM '["account"]'::jsonb
            OR (owner_rule#>ARRAY['children',move->>'child_index','resources'] ? 'project') IS DISTINCT FROM true THEN
            CONTINUE;
        END IF;
        names:=coalesce(nullif(owner_rule->'resource_names','null'::jsonb),'[]'::jsonb);
        ordinary:=coalesce(nullif(owner_rule->'match_labels','null'::jsonb),'{}'::jsonb);
        protected:=coalesce(owner_rule->'match_access_labels','{}'::jsonb);
        used_rows:=used_rows+1+jsonb_array_length(names)
            +(SELECT count(*) FROM jsonb_object_keys(ordinary))
            +(SELECT count(*) FROM jsonb_object_keys(protected));
        IF used_rows>p_rows THEN RAISE EXCEPTION 'project owner predicates exceed budget' USING ERRCODE='54000';END IF;
        plan:=jsonb_build_object('object_types',jsonb_build_array('iam.account'),'resource_names',names,
            'match_labels',ordinary,'match_access_labels',protected,'arm',CASE WHEN protected<>'{}'::jsonb THEN 'access_labels'
            WHEN names<>'[]'::jsonb THEN 'names' WHEN ordinary<>'{}'::jsonb THEN 'labels' ELSE 'anchor' END);
        bytes:=bytes+octet_length(plan::text)+2;
        IF bytes>8388608 THEN RAISE EXCEPTION 'project owner plan exceeds byte budget' USING ERRCODE='54000';END IF;
        predicates:=array_append(predicates,plan);
    END LOOP;
    SELECT coalesce(jsonb_agg(DISTINCT predicate ORDER BY predicate),'[]'::jsonb)
      INTO plan FROM unnest(predicates) predicate;
    RETURN jsonb_build_object('predicates',plan,'rows',used_rows);
END;
$owners$;

-- Верхняя граница контейнеров для OLD-правила над iam.account. Конечные ID
-- ещё требуют удержания строки (или её отсутствия) и проверки OLD-селектора.
CREATE FUNCTION kaname._authority_role_move_project_container_scopes_v1(
    p_holders jsonb,p_rows integer
) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $scopes$
DECLARE
    forbidden constant text:=U&'[:#*\0001-\0020\007F-\00A0\1680\2000-\200A\2028\2029\202F\205F\3000]';
    holder record;
    scope jsonb;
    scope_kind text;
    scope_id text;
    target jsonb;
    resources jsonb;
    target_count integer;
    ref jsonb;
    account_selected boolean;
    all_accounts boolean:=false;
    account_ids text[]:=ARRAY[]::text[];
    ids jsonb;
    used_rows integer:=0;
BEGIN
    IF jsonb_typeof(p_holders) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'invalid project container holder map' USING ERRCODE='42501';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000 OR octet_length(p_holders::text)>8388608 THEN
        RAISE EXCEPTION 'project container holder input exceeds budget' USING ERRCODE='54000';
    END IF;
    -- Порядок выдач не влияет на множество. Сортируем только оплаченные ID.
    FOR holder IN SELECT key,value FROM jsonb_each(p_holders) LIMIT p_rows+1 LOOP
        used_rows:=used_rows+1;
        IF used_rows>p_rows THEN
            RAISE EXCEPTION 'project container holders exceed budget' USING ERRCODE='54000';
        END IF;
        IF octet_length(holder.key) NOT BETWEEN 1 AND 16384 OR holder.key COLLATE "C" ~ forbidden
            OR jsonb_typeof(holder.value) IS DISTINCT FROM 'object'
            OR NOT (holder.value ?& ARRAY['class','expires_at','scope','target','subjects','binding_tuples'])
            OR holder.value-ARRAY['class','expires_at','scope','target','subjects','binding_tuples']<>'{}'::jsonb
            OR jsonb_typeof(holder.value->'class') IS DISTINCT FROM 'string'
            OR holder.value->>'class' NOT IN ('ACTIVE','PENDING')
            OR jsonb_typeof(holder.value->'expires_at') NOT IN ('string','null')
            OR jsonb_typeof(holder.value->'subjects') IS DISTINCT FROM 'array'
            OR jsonb_typeof(holder.value->'binding_tuples') IS DISTINCT FROM 'array' THEN
            RAISE EXCEPTION 'invalid held project container binding' USING ERRCODE='42501';
        END IF;
        -- Строки получателей и кортежи уже удостоверены владельцем выдачи.
        IF jsonb_array_length(holder.value->'subjects') NOT BETWEEN 1 AND 32
            OR jsonb_array_length(holder.value->'binding_tuples') <>
                (CASE holder.value->>'class' WHEN 'ACTIVE' THEN 1 ELSE 0 END) THEN
            RAISE EXCEPTION 'invalid held project container binding bounds' USING ERRCODE='42501';
        END IF;
        scope:=holder.value->'scope';
        target:=holder.value->'target';
        resources:=coalesce(target->'resources','[]'::jsonb);
        IF jsonb_typeof(scope) IS DISTINCT FROM 'array'
            OR jsonb_typeof(scope->0) IS DISTINCT FROM 'string' OR jsonb_typeof(scope->1) IS DISTINCT FROM 'string'
            OR jsonb_typeof(target) IS DISTINCT FROM 'object'
            OR target-ARRAY['allInScope','resources']<>'{}'::jsonb
            OR (target ? 'allInScope' AND jsonb_typeof(target->'allInScope') IS DISTINCT FROM 'boolean')
            OR jsonb_typeof(resources) IS DISTINCT FROM 'array' THEN
            RAISE EXCEPTION 'invalid project container scope or target' USING ERRCODE='42501';
        END IF;
        scope_kind:=scope->>0;
        scope_id:=scope->>1;
        target_count:=jsonb_array_length(resources);
        IF jsonb_array_length(scope)<>2 OR scope_kind NOT IN ('account','project','cluster')
            OR octet_length(scope_id) NOT BETWEEN 1 AND 16384 OR scope_id COLLATE "C" ~ forbidden
            OR (scope_kind='cluster' AND scope_id<>'cluster_root')
            OR target_count>256 OR (target_count>0 AND target->'allInScope'='true'::jsonb) THEN
            RAISE EXCEPTION 'invalid project container scope or target bounds' USING ERRCODE='42501';
        END IF;
        -- Валидируем все конечные ссылки, в том числе для заведомо пустой
        -- области проекта. Пустая карта цели и пустой resources означают всю область.
        used_rows:=used_rows+target_count;
        IF used_rows>p_rows THEN
            RAISE EXCEPTION 'project container target checks exceed budget' USING ERRCODE='54000';
        END IF;
        IF EXISTS(SELECT FROM jsonb_array_elements(resources) r
            WHERE jsonb_typeof(r) IS DISTINCT FROM 'object'
                OR r-ARRAY['type','id']<>'{}'::jsonb
                OR jsonb_typeof(r->'type') IS DISTINCT FROM 'string'
                OR jsonb_typeof(r->'id') IS DISTINCT FROM 'string'
                OR octet_length(r->>'type') NOT BETWEEN 1 AND 16384 OR (r->>'type') COLLATE "C" ~ forbidden
                OR octet_length(r->>'id') NOT BETWEEN 1 AND 16384 OR (r->>'id') COLLATE "C" ~ forbidden) THEN
            RAISE EXCEPTION 'invalid finite project container target' USING ERRCODE='42501';
        END IF;
        IF scope_kind='project' THEN CONTINUE;END IF;
        IF target_count=0 THEN
            IF scope_kind='cluster' THEN all_accounts:=true;
            ELSE account_ids:=array_append(account_ids,scope_id);END IF;
            CONTINUE;
        END IF;
        used_rows:=used_rows+target_count;
        IF used_rows>p_rows THEN
            RAISE EXCEPTION 'project container target selection exceeds budget' USING ERRCODE='54000';
        END IF;
        account_selected:=false;
        FOR ref IN SELECT value FROM jsonb_array_elements(resources) LOOP
            IF ref->>'type'<>'iam.account' THEN CONTINUE;END IF;
            IF scope_kind='cluster' THEN
                account_ids:=array_append(account_ids,ref->>'id');
            ELSIF ref->>'id'=scope_id THEN
                account_selected:=true;
            END IF;
        END LOOP;
        IF account_selected THEN account_ids:=array_append(account_ids,scope_id);END IF;
    END LOOP;
    used_rows:=used_rows+cardinality(account_ids);
    IF used_rows>p_rows THEN
        RAISE EXCEPTION 'project container ID set exceeds budget' USING ERRCODE='54000';
    END IF;
    SELECT coalesce(jsonb_agg(id ORDER BY id COLLATE "C"),'[]'::jsonb) INTO ids
      FROM (SELECT DISTINCT candidate COLLATE "C" AS id FROM unnest(account_ids) candidate) distinct_ids;
    RETURN jsonb_build_object('ids',ids,'all_accounts',all_accounts,'rows',used_rows);
END;
$scopes$;

-- Области и цели берутся из полной удержанной переписи привязок роли.
-- Снимок включает все реально выбранные нативные аккаунты, включая пустой набор.
CREATE FUNCTION kaname._authority_role_move_project_bound_accounts_v1(
    p_predicates jsonb,p_holders jsonb,p_expected jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $bound_accounts$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    scopes jsonb;
    account_ids text[];
    bounded boolean;
    predicate jsonb;
    named_only boolean;
    selected boolean;
    row_labels integer;
    cap integer;
    r record;
    images jsonb[]:=ARRAY[]::jsonb[];
    image jsonb;
    source jsonb;
    ids jsonb;
    bytes bigint:=2;
    used_rows integer:=2;
    used_reads integer:=3;
    returned_rows integer;
BEGIN
    IF jsonb_typeof(p_predicates) IS DISTINCT FROM 'array' OR p_predicates='[]'::jsonb
        OR jsonb_typeof(p_holders) IS DISTINCT FROM 'object' OR p_holders='{}'::jsonb
        OR (p_expected IS NOT NULL AND jsonb_typeof(p_expected) IS DISTINCT FROM 'object') THEN
        RAISE EXCEPTION 'invalid bound project account input' USING ERRCODE='42501';
    END IF;
    used_rows:=used_rows+jsonb_array_length(p_predicates);
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN
        RAISE EXCEPTION 'bound project accounts exceed budget' USING ERRCODE='54000';
    END IF;
    scopes:=kaname._authority_role_move_project_container_scopes_v1(p_holders,p_rows-used_rows);
    used_rows:=used_rows+(scopes->>'rows')::integer;
    bounded:=scopes->'all_accounts'='false'::jsonb;
    SELECT coalesce(array_agg(value),ARRAY[]::text[]) INTO account_ids FROM jsonb_array_elements_text(scopes->'ids');
    IF p_expected IS NULL THEN
        LOCK TABLE ONLY kaname.catalog_resource, ONLY kaname.resource_mirror, ONLY kaname.resource_parent_edge,
            ONLY kaname.accounts IN SHARE MODE NOWAIT;
    END IF;
    IF NOT EXISTS(SELECT FROM pg_class c JOIN pg_locks l ON l.relation=c.oid
        WHERE c.oid='kaname.accounts'::regclass AND c.relowner=current_user::regrole AND c.relkind='r' AND c.relpersistence='p'
            AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relispartition OR c.relhasrules)
            AND NOT EXISTS(SELECT FROM pg_inherits h WHERE h.inhparent=c.oid OR h.inhrelid=c.oid)
            AND has_table_privilege((proof->>'invoker_oid')::oid,c.oid,'SELECT')
            AND l.pid=pg_backend_pid() AND l.granted AND l.locktype='relation' AND l.mode='ShareLock'
            AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
            AND EXISTS(SELECT FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid
                JOIN pg_am am ON am.oid=idx.relam
                JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=i.indkey[0] AND a.attname='id'
                WHERE i.indrelid=c.oid AND i.indnkeyatts=1 AND am.amname='btree'
                    AND i.indisunique AND i.indisvalid AND i.indisready AND i.indimmediate
                    AND i.indpred IS NULL AND i.indexprs IS NULL)) THEN
        RAISE EXCEPTION 'bound project account custody differs' USING ERRCODE='42501';
    END IF;

    -- Без конечной цели запрос по именованным OLD-ветвям всё ещё конечен.
    IF NOT bounded THEN
        SELECT NOT EXISTS(SELECT FROM jsonb_array_elements(p_predicates) p WHERE p->>'arm'<>'names') INTO named_only;
        IF named_only THEN
            SELECT coalesce(array_agg(DISTINCT n),ARRAY[]::text[]) INTO account_ids
            FROM jsonb_array_elements(p_predicates) p CROSS JOIN LATERAL jsonb_array_elements_text(p->'resource_names') n;
            bounded:=true;
        END IF;
    END IF;
    used_rows:=used_rows+cardinality(account_ids);
    IF used_rows>p_rows OR used_reads>=p_reads THEN
        RAISE EXCEPTION 'bound project account scans exceed budget' USING ERRCODE='54000';
    END IF;
    cap:=least(4096,p_rows-used_rows);
    used_reads:=used_reads+1;
    returned_rows:=0;
    -- Для широкой области ограничиваем физические строки до фильтра.
    -- Конечные области и имена используют ключ id, пустой список даёт ноль.
    FOR r IN EXECUTE 'SELECT a.id,a.xmin::text x,a.ctid::text t,a.labels,a.access_labels FROM ONLY kaname.accounts a'
        ||CASE WHEN bounded THEN ' WHERE a.id=ANY($1)' ELSE '' END||' LIMIT $2'
        USING account_ids,cap+1
    LOOP
        returned_rows:=returned_rows+1;
        used_rows:=used_rows+1;
        IF returned_rows>cap OR used_rows>p_rows THEN
            RAISE EXCEPTION 'bound project account census exceeds budget' USING ERRCODE='54000';
        END IF;
        IF jsonb_typeof(r.labels) IS DISTINCT FROM 'object'
            OR kaname.access_labels_valid_v1(r.access_labels) IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'invalid bound project account labels' USING ERRCODE='42501';
        END IF;
        row_labels:=(SELECT count(*) FROM jsonb_object_keys(r.labels))+
            (SELECT count(*) FROM jsonb_object_keys(r.access_labels));
        used_rows:=used_rows+row_labels;
        IF used_rows>p_rows THEN RAISE EXCEPTION 'bound project account labels exceed budget' USING ERRCODE='54000';END IF;
        selected:=false;
        FOR predicate IN SELECT value FROM jsonb_array_elements(p_predicates) LOOP
            used_rows:=used_rows+1+jsonb_array_length(predicate->'resource_names')
                +(SELECT count(*) FROM jsonb_object_keys(predicate->'match_labels'))
                +(SELECT count(*) FROM jsonb_object_keys(predicate->'match_access_labels'));
            IF used_rows>p_rows THEN
                RAISE EXCEPTION 'bound project account predicates exceed budget' USING ERRCODE='54000';
            END IF;
            IF kaname._authority_resource_selector_matches_v3(predicate,'iam.account',r.id,r.labels,r.access_labels) THEN
                selected:=true;
                EXIT;
            END IF;
        END LOOP;
        image:=jsonb_build_array(r.id,r.x,r.t,selected);
        bytes:=bytes+octet_length(image::text)+2;
        IF bytes>8388608 THEN
            RAISE EXCEPTION 'bound project owner receipt exceeds byte budget' USING ERRCODE='54000';
        END IF;
        images:=array_append(images,image);
    END LOOP;
    SELECT coalesce(jsonb_agg(v->0 ORDER BY (v->>0) COLLATE "C")
            FILTER(WHERE v->3='true'::jsonb),'[]'::jsonb),
        jsonb_build_object('count',count(*),'sha256',encode(sha256(convert_to(
            coalesce(jsonb_agg(v ORDER BY (v->>0) COLLATE "C"),'[]'::jsonb)::text,'UTF8')),'hex'))
        INTO ids,source FROM unnest(images) v;
    IF p_expected IS NOT NULL AND source IS DISTINCT FROM p_expected THEN
        RAISE EXCEPTION 'bound project owner matches changed after preparation' USING ERRCODE='40001';
    END IF;
    RETURN jsonb_build_object('source',source,'account_ids',ids,'rows',used_rows,'reads',used_reads);
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'bound project account sources busy' USING ERRCODE='40001';
END;
$bound_accounts$;

-- Удерживает нативные проекты прямых OLD-селекторов. Исходные области
-- остаются теми же после истечения выдач, итоговые пары выбираются заново.
CREATE FUNCTION kaname._authority_role_move_project_direct_census_v1(
    p_role jsonb,p_moves jsonb,p_prepared_holders jsonb,p_holders jsonb,p_definition boolean,
    p_replay boolean,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $direct$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    forbidden constant text:=U&'[:#*\0001-\0020\007F-\00A0\1680\2000-\200A\2028\2029\202F\205F\3000]';
    move jsonb;
    rule_image jsonb;
    labels jsonb;
    selectors jsonb[]:=ARRAY[]::jsonb[];
    scope jsonb;
    holder jsonb;
    resources jsonb;
    account_ids text[]:=ARRAY[]::text[];
    project_ids text[]:=ARRAY[]::text[];
    all_projects boolean:=false;
    scope_filter text;
    r record;
    cap integer;
    returned_rows integer:=0;
    source_images jsonb[]:=ARRAY[]::jsonb[];
    selected_ids text[]:=ARRAY[]::text[];
    granted_roots jsonb[]:=ARRAY[]::jsonb[];
    selector jsonb;
    permitted boolean;
    pairs jsonb;
    sources jsonb;
    ids jsonb;
    result jsonb;
    used_rows integer;
    used_reads integer:=1;
    bytes bigint:=2;
BEGIN
    IF jsonb_typeof(p_role->'rules') IS DISTINCT FROM 'array' OR jsonb_typeof(p_moves) IS DISTINCT FROM 'array'
        OR jsonb_typeof(p_prepared_holders) IS DISTINCT FROM 'object' OR jsonb_typeof(p_holders) IS DISTINCT FROM 'object'
        OR p_definition IS NULL OR p_replay IS NULL OR NOT (p_prepared_holders @> p_holders)
        OR p_definition IS DISTINCT FROM (p_prepared_holders='{}'::jsonb) THEN
        RAISE EXCEPTION 'invalid direct project copy census input' USING ERRCODE='42501';
    END IF;
    used_rows:=jsonb_array_length(p_moves);
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN
        RAISE EXCEPTION 'direct project census exceeds input budget' USING ERRCODE='54000';
    END IF;
    FOR move IN SELECT value FROM jsonb_array_elements(p_moves) LOOP
        IF move->>'child_index'<>'-1' THEN CONTINUE;END IF;
        rule_image:=p_role#>ARRAY['rules',move->>'rule_index'];
        IF rule_image->'module' IS DISTINCT FROM '"iam"'::jsonb
            OR (rule_image->'resources' ? 'project') IS DISTINCT FROM true THEN CONTINUE;END IF;
        labels:=rule_image->'match_labels';
        IF kaname.access_labels_valid_v1(labels) IS DISTINCT FROM true OR labels='{}'::jsonb THEN
            RAISE EXCEPTION 'invalid direct project OLD predicate' USING ERRCODE='42501';
        END IF;
        used_rows:=used_rows+1+(SELECT count(*) FROM jsonb_object_keys(labels));
        IF used_rows>p_rows THEN RAISE EXCEPTION 'direct project predicates exceed budget' USING ERRCODE='54000';END IF;
        selectors:=array_append(selectors,jsonb_build_object('object_types','["iam.project"]'::jsonb,
            'arm','labels','match_labels',labels));
    END LOOP;
    IF cardinality(selectors)=0 THEN
        RETURN jsonb_build_object('ids','[]'::jsonb,'pairs','{}'::jsonb,'source',NULL,'rows',used_rows,'reads',used_reads);
    END IF;

    IF p_definition THEN
        IF p_role->'is_system' IS DISTINCT FROM 'false'::jsonb OR coalesce(p_role->>'cluster_id','')<>''
            OR coalesce(p_role->>'owner_module','')<>''
            OR (coalesce(p_role->>'account_id','')='')=(coalesce(p_role->>'project_id','')='') THEN
            RAISE EXCEPTION 'invalid direct project copy definition scope' USING ERRCODE='42501';
        END IF;
        IF coalesce(p_role->>'account_id','')<>'' THEN account_ids:=ARRAY[p_role->>'account_id'];
        ELSE project_ids:=ARRAY[p_role->>'project_id'];END IF;
    ELSE
        -- Переиспользуем проверку полного формата областей и конечных целей.
        scope:=kaname._authority_role_move_project_container_scopes_v1(p_prepared_holders,p_rows-used_rows);
        used_rows:=used_rows+(scope->>'rows')::integer;
        FOR holder IN SELECT value FROM jsonb_each(p_prepared_holders) LOOP
            resources:=coalesce(holder#>'{target,resources}','[]'::jsonb);
            used_rows:=used_rows+1+jsonb_array_length(resources);
            IF used_rows>p_rows THEN RAISE EXCEPTION 'direct project scopes exceed budget' USING ERRCODE='54000';END IF;
            IF resources='[]'::jsonb THEN
                CASE holder#>>'{scope,0}'
                WHEN 'account' THEN account_ids:=array_append(account_ids,holder#>>'{scope,1}');
                WHEN 'project' THEN project_ids:=array_append(project_ids,holder#>>'{scope,1}');
                WHEN 'cluster' THEN all_projects:=true;
                END CASE;
            ELSE
                project_ids:=project_ids||ARRAY(SELECT ref->>'id' FROM jsonb_array_elements(resources) ref
                    WHERE ref->>'type'='iam.project'
                      AND (holder#>>'{scope,0}'<>'project' OR holder#>>'{scope,1}'=ref->>'id'));
            END IF;
        END LOOP;
    END IF;
    used_rows:=used_rows+cardinality(account_ids)+cardinality(project_ids);
    IF used_rows>p_rows OR p_reads-used_reads<3 THEN
        RAISE EXCEPTION 'direct project source scopes exceed budget' USING ERRCODE='54000';
    END IF;
    IF NOT all_projects AND cardinality(account_ids)=0 AND cardinality(project_ids)=0 THEN
        RETURN jsonb_build_object('ids','[]'::jsonb,'pairs','{}'::jsonb,
            'source',jsonb_build_object('count',0,'sha256',encode(sha256(convert_to('[]','UTF8')),'hex')),
            'rows',used_rows,'reads',used_reads);
    END IF;
    IF NOT p_replay THEN LOCK TABLE ONLY kaname.projects IN SHARE MODE NOWAIT;END IF;
    IF NOT EXISTS(SELECT FROM pg_class c JOIN pg_locks l ON l.relation=c.oid
        WHERE c.oid='kaname.projects'::regclass AND c.relowner=current_user::regrole AND c.relkind='r' AND c.relpersistence='p'
            AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relispartition OR c.relhasrules)
            AND NOT EXISTS(SELECT FROM pg_inherits h WHERE h.inhparent=c.oid OR h.inhrelid=c.oid)
            AND has_table_privilege((proof->>'invoker_oid')::oid,c.oid,'SELECT')
            AND l.pid=pg_backend_pid() AND l.granted AND l.locktype='relation' AND l.mode='ShareLock'
            AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
            AND EXISTS(SELECT FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid
                JOIN pg_am am ON am.oid=idx.relam
                JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=i.indkey[0] AND a.attname='id'
                WHERE i.indrelid=c.oid AND i.indnkeyatts=1 AND am.amname='btree'
                    AND i.indisunique AND i.indisvalid AND i.indisready AND i.indimmediate
                    AND i.indpred IS NULL AND i.indexprs IS NULL)
            AND (all_projects OR cardinality(account_ids)=0 OR EXISTS(
                SELECT FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid
                JOIN pg_am am ON am.oid=idx.relam
                JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=i.indkey[0] AND a.attname='account_id'
                WHERE i.indrelid=c.oid AND am.amname='btree' AND i.indisvalid AND i.indisready
                    AND i.indpred IS NULL AND i.indexprs IS NULL))) THEN
        RAISE EXCEPTION 'direct project source custody differs' USING ERRCODE='42501';
    END IF;
    used_reads:=used_reads+3;
    cap:=least(4096,p_rows-used_rows);
    -- Сначала ограничиваем физический набор исходных областей и целей.
    -- OLD-метки проверяются в цикле, поэтому несовпадения тоже оплачены.
    scope_filter:=CASE WHEN all_projects THEN ''
        WHEN cardinality(account_ids)=0 THEN ' WHERE p.id=ANY($2)'
        WHEN cardinality(project_ids)=0 THEN ' WHERE p.account_id=ANY($1)'
        ELSE ' WHERE p.account_id=ANY($1) OR p.id=ANY($2)' END;
    FOR r IN EXECUTE 'SELECT p.id,p.account_id,p.xmin::text x,p.ctid::text t,p.labels FROM ONLY kaname.projects p'
        ||scope_filter||' LIMIT $3' USING account_ids,project_ids,cap+1
    LOOP
        returned_rows:=returned_rows+1;
        used_rows:=used_rows+1;
        IF returned_rows>cap OR used_rows>p_rows THEN
            RAISE EXCEPTION 'direct project physical census exceeds budget' USING ERRCODE='54000';
        END IF;
        bytes:=bytes+octet_length(r.id)+octet_length(r.account_id)+64;
        IF bytes>8388608 OR octet_length(r.labels::text)>8388608 THEN
            RAISE EXCEPTION 'direct project source exceeds byte budget' USING ERRCODE='54000';
        END IF;
        source_images:=array_append(source_images,jsonb_build_array(r.id,r.x,r.t,r.account_id));
        pairs:='{}'::jsonb;
        FOREACH selector IN ARRAY selectors LOOP
            used_rows:=used_rows+1+(SELECT count(*) FROM jsonb_object_keys(selector->'match_labels'));
            IF used_rows>p_rows THEN RAISE EXCEPTION 'direct project matching exceeds budget' USING ERRCODE='54000';END IF;
            IF kaname._authority_resource_selector_matches_v3(selector,'iam.project',r.id,r.labels,'{}'::jsonb) THEN
                pairs:=pairs||(selector->'match_labels');
            END IF;
        END LOOP;
        IF pairs='{}'::jsonb THEN CONTINUE;END IF;
        IF coalesce(r.id,'')='' OR octet_length(r.id)>16384 OR r.id COLLATE "C" ~ forbidden
            OR coalesce(r.account_id,'')='' OR octet_length(r.account_id)>16384 OR r.account_id COLLATE "C" ~ forbidden THEN
            RAISE EXCEPTION 'invalid direct project or owner account identity' USING ERRCODE='42501';
        END IF;
        selected_ids:=array_append(selected_ids,r.id);
        permitted:=p_definition;
        IF NOT p_definition THEN
            FOR holder IN SELECT value FROM jsonb_each(p_holders) LOOP
                used_rows:=used_rows+1+jsonb_array_length(coalesce(holder#>'{target,resources}','[]'::jsonb));
                IF used_rows>p_rows THEN RAISE EXCEPTION 'direct project holder matching exceeds budget' USING ERRCODE='54000';END IF;
                IF kaname._authority_resource_contained_v2(holder#>>'{scope,0}',holder#>>'{scope,1}',
                        jsonb_build_array(r.account_id),r.id)
                    AND kaname._authority_resource_target_contains_v2(holder->'target','iam.project',r.id) THEN
                    permitted:=true;
                    EXIT;
                END IF;
            END LOOP;
        END IF;
        IF permitted THEN
            bytes:=bytes+octet_length(pairs::text)+octet_length(r.id)+4;
            IF bytes>8388608 THEN RAISE EXCEPTION 'direct project pairs exceed byte budget' USING ERRCODE='54000';END IF;
            granted_roots:=array_append(granted_roots,jsonb_build_array(r.id,pairs));
        END IF;
    END LOOP;
    SELECT coalesce(jsonb_agg(id ORDER BY id COLLATE "C"),'[]'::jsonb) INTO ids FROM unnest(selected_ids) id;
    SELECT jsonb_build_object('count',count(*),'sha256',encode(sha256(convert_to(
        coalesce(jsonb_agg(v ORDER BY (v->>0) COLLATE "C"),'[]'::jsonb)::text,'UTF8')),'hex'))
      INTO sources FROM unnest(source_images) v;
    SELECT jsonb_build_object('ids',ids,'pairs',coalesce(jsonb_object_agg(v->>0,v->1),'{}'::jsonb),
        'source',sources,'rows',used_rows,'reads',used_reads)
      INTO result FROM unnest(granted_roots) v;
    RETURN result;
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'direct project sources busy' USING ERRCODE='40001';
END;
$direct$;

-- Применяет полный OLD-селектор к независимо обнаруженным проектам.
-- Отпечаток физических строк сохраняется и для проектов без копий.
CREATE FUNCTION kaname._authority_role_move_project_census_matches_v1(
    p_role jsonb,p_moves jsonb,p_project_ids jsonb,p_prepared_holders jsonb,p_holders jsonb,
    p_definition boolean,p_replay boolean,p_copies jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $matches$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    scope_account_id text:=p_role->>'account_id';
    forbidden constant text:=U&'[:#*\0001-\0020\007F-\00A0\1680\2000-\200A\2028\2029\202F\205F\3000]';
    root_id text;
    mirror jsonb;
    native jsonb;
    parent_id text;
    fallback_account text;
    fallback_image jsonb;
    resolved_account text;
    graph jsonb;
    support jsonb;
    pairs jsonb;
    protected jsonb;
    required jsonb;
    conflicts boolean;
    pair_count integer;
    coordinate jsonb;
    sources jsonb[]:=ARRAY[]::jsonb[];
    proposed jsonb;
    covers_project_moves boolean;
    direct jsonb;
    all_project_ids jsonb;
    nested_ids jsonb;
    direct_ids jsonb;
    nested_scope boolean;
    nested_pairs jsonb;
    direct_pairs jsonb;
    combined jsonb;
    used_rows integer;
    used_reads integer:=3;
    output_bytes bigint:=2;
BEGIN
    IF jsonb_typeof(p_project_ids) IS DISTINCT FROM 'array'
        OR jsonb_typeof(p_copies) IS DISTINCT FROM 'array' OR p_definition IS NULL
        OR jsonb_typeof(p_holders) IS DISTINCT FROM 'object'
        OR jsonb_typeof(p_moves) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'invalid project match census input' USING ERRCODE='42501';
    END IF;
    used_rows:=2+jsonb_array_length(p_project_ids)+jsonb_array_length(p_copies)+jsonb_array_length(p_moves);
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096
        OR octet_length(p_copies::text)>8388608 THEN
        RAISE EXCEPTION 'project match census exceeds budget' USING ERRCODE='54000';
    END IF;
    IF NOT EXISTS(SELECT FROM pg_class c WHERE c.oid='kaname.projects'::regclass
        AND c.relowner=current_user::regrole AND c.relkind='r' AND c.relpersistence='p'
        AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relispartition OR c.relhasrules)
        AND NOT EXISTS(SELECT FROM pg_inherits h WHERE h.inhparent=c.oid OR h.inhrelid=c.oid)
        AND has_table_privilege((proof->>'invoker_oid')::oid,c.oid,'SELECT')
        AND EXISTS(SELECT FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid
            JOIN pg_am am ON am.oid=idx.relam
            JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=i.indkey[0] AND a.attname='id'
            WHERE i.indrelid=c.oid AND i.indnkeyatts=1 AND am.amname='btree'
                AND i.indisunique AND i.indisvalid AND i.indisready AND i.indimmediate
                AND i.indpred IS NULL AND i.indexprs IS NULL)) THEN
        RAISE EXCEPTION 'project census native custody differs' USING ERRCODE='42501';
    END IF;
    SELECT coalesce(jsonb_object_agg(c->>'root_id',c->'new_access_labels'),'{}'::jsonb)
      INTO proposed FROM jsonb_array_elements(p_copies) c
     WHERE c->>'root_type'='iam.project' AND jsonb_typeof(c->'root_id')='string';
    SELECT NOT EXISTS(SELECT FROM jsonb_array_elements(p_moves) m
        WHERE m->>'child_index'<>'-1'
            AND p_role#>ARRAY['rules',m->>'rule_index','module']='"iam"'::jsonb
            AND p_role#>ARRAY['rules',m->>'rule_index','children',m->>'child_index','resources'] ? 'project'
            AND p_role#>ARRAY['rules',m->>'rule_index','resources'] IS DISTINCT FROM '["account"]'::jsonb)
        INTO covers_project_moves;
    direct:=kaname._authority_role_move_project_direct_census_v1(
        p_role,p_moves,p_prepared_holders,p_holders,p_definition,p_replay,p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(direct->>'rows')::integer+jsonb_array_length(direct->'ids');
    used_reads:=used_reads+(direct->>'reads')::integer;
    IF used_rows>p_rows THEN RAISE EXCEPTION 'project union exceeds budget' USING ERRCODE='54000';END IF;
    SELECT coalesce(jsonb_object_agg(id,true),'{}'::jsonb) INTO nested_ids
        FROM jsonb_array_elements_text(p_project_ids) id;
    SELECT coalesce(jsonb_object_agg(id,true),'{}'::jsonb) INTO direct_ids
        FROM jsonb_array_elements_text(direct->'ids') id;
    SELECT coalesce(jsonb_agg(id ORDER BY id COLLATE "C"),'[]'::jsonb) INTO all_project_ids
        FROM jsonb_object_keys(nested_ids||direct_ids) id;
    IF covers_project_moves AND EXISTS(SELECT id FROM jsonb_object_keys(proposed) id
        EXCEPT SELECT value FROM jsonb_array_elements_text(all_project_ids)) THEN
        RAISE EXCEPTION 'project copy proposal contains a project outside the OLD selector census' USING ERRCODE='40001';
    END IF;
    FOR root_id IN SELECT value FROM jsonb_array_elements_text(all_project_ids) LOOP
        nested_scope:=nested_ids ? root_id;
        mirror:=NULL;
        graph:=NULL;
        parent_id:=NULL;
        fallback_image:=NULL;
        IF nested_scope THEN
            IF p_rows-used_rows<2 OR p_reads-used_reads<2 THEN
                RAISE EXCEPTION 'role move project copy sources exceed budget' USING ERRCODE='54000';
            END IF;
            SELECT jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) INTO mirror
            FROM ONLY kaname.resource_mirror m WHERE m.object_type='iam.project' AND m.object_id=root_id;
            IF mirror IS NULL THEN
                RAISE EXCEPTION 'role move project mirror changed since reverse census' USING ERRCODE='40001';
            END IF;
            used_rows:=used_rows+1;
            used_reads:=used_reads+1;
            parent_id:=nullif(mirror#>>'{2,parent_project_id}','');
            IF p_definition AND parent_id IS NOT NULL THEN
                IF octet_length(parent_id)>16384 OR parent_id COLLATE "C" ~ forbidden THEN
                    RAISE EXCEPTION 'invalid role move project fallback identity' USING ERRCODE='42501';
                END IF;
                IF p_rows-used_rows<2 OR p_reads-used_reads<3 THEN
                    RAISE EXCEPTION 'role move project fallback exceeds budget' USING ERRCODE='54000';
                END IF;
                IF NOT pg_try_advisory_xact_lock_shared(1262569303,hashtext(kaname._authority_crud_unique_key_v3(
                    'projects',jsonb_build_object('id',parent_id)))) THEN
                    RAISE EXCEPTION 'role move project fallback is being written' USING ERRCODE='40001';
                END IF;
                SELECT jsonb_build_array(p.xmin::text,p.ctid::text,p.account_id) INTO fallback_image
                FROM ONLY kaname.projects p WHERE p.id=parent_id FOR SHARE OF p NOWAIT;
                used_rows:=used_rows+1;
                used_reads:=used_reads+2;
            END IF;
            IF p_definition THEN
                fallback_account:=fallback_image->>2;
                resolved_account:=coalesce(nullif(mirror#>>'{2,parent_account_id}',''),fallback_account);
                IF resolved_account IS DISTINCT FROM scope_account_id AND fallback_account IS NOT DISTINCT FROM scope_account_id THEN
                    RAISE EXCEPTION 'role move project mirror contradicts its fallback scope' USING ERRCODE='40001';
                END IF;
                nested_scope:=resolved_account IS NOT DISTINCT FROM scope_account_id;
            END IF;
        END IF;
        IF NOT nested_scope AND NOT (direct_ids ? root_id) THEN
            IF covers_project_moves AND proposed ? root_id THEN
                RAISE EXCEPTION 'project copy proposal contains a project outside the role definition scope' USING ERRCODE='40001';
            END IF;
            coordinate:=jsonb_build_array(root_id,'outside',parent_id,fallback_image);
        ELSE
            IF used_rows>=p_rows OR used_reads>=p_reads THEN
                RAISE EXCEPTION 'role move project native reads exceed budget' USING ERRCODE='54000';
            END IF;
            SELECT jsonb_build_array(p.xmin::text,p.ctid::text,to_jsonb(p)) INTO native
            FROM ONLY kaname.projects p WHERE p.id=root_id FOR SHARE OF p NOWAIT;
            IF native IS NULL OR kaname.access_labels_valid_v1(native#>'{2,access_labels}') IS DISTINCT FROM true THEN
                RAISE EXCEPTION 'role move project native row missing or invalid' USING ERRCODE='40001';
            END IF;
            used_rows:=used_rows+1;
            used_reads:=used_reads+1;
            nested_pairs:='{}'::jsonb;
            IF nested_scope THEN
                graph:=kaname._authority_role_move_project_copy_graph_hold_v1(
                    root_id,native,mirror,p_rows-used_rows,p_reads-used_reads);
                used_rows:=used_rows+(graph->>'rows')::integer;
                used_reads:=used_reads+(graph->>'reads')::integer;
                support:=kaname._authority_role_move_project_copy_support_v1(
                    graph,p_role,p_moves,p_definition,p_holders,p_rows-used_rows);
                used_rows:=used_rows+(support->>'rows')::integer;
                pairs:=kaname._authority_role_move_project_copy_pairs_v1(support,p_holders,p_rows-used_rows);
                used_rows:=used_rows+(pairs->>'rows')::integer;
                nested_pairs:=pairs->'pairs';
            END IF;
            direct_pairs:=coalesce(direct->'pairs'->root_id,'{}'::jsonb);
            pair_count:=(SELECT count(*) FROM jsonb_object_keys(direct_pairs))+
                (SELECT count(*) FROM jsonb_object_keys(nested_pairs));
            used_rows:=used_rows+3*pair_count;
            IF used_rows>p_rows THEN RAISE EXCEPTION 'role move project copy pairs exceed budget' USING ERRCODE='54000';END IF;
            IF EXISTS(SELECT FROM jsonb_each(nested_pairs) n WHERE direct_pairs ? n.key
                AND direct_pairs->n.key IS DISTINCT FROM n.value) THEN
                RAISE EXCEPTION 'direct and nested project OLD selectors disagree' USING ERRCODE='40001';
            END IF;
            combined:=direct_pairs||nested_pairs;
            protected:=native#>'{2,access_labels}';
            SELECT coalesce(jsonb_object_agg(x.key,x.value) FILTER(WHERE NOT (protected ? x.key)),'{}'::jsonb),
                coalesce(bool_or(protected ? x.key AND protected->x.key IS DISTINCT FROM x.value),false)
              INTO required,conflicts FROM jsonb_each(combined) x;
            IF conflicts THEN
                RAISE EXCEPTION 'role move project copy conflicts with protected labels' USING ERRCODE='40001';
            END IF;
            IF required<>'{}'::jsonb AND ((proposed->root_id) @> required) IS DISTINCT FROM true THEN
                RAISE EXCEPTION 'project copy proposal omits an OLD selector match' USING ERRCODE='40001';
            END IF;
            IF covers_project_moves AND coalesce(proposed->root_id,protected) IS DISTINCT FROM (protected||required) THEN
                RAISE EXCEPTION 'project copy proposal retains a pair without effective OLD support' USING ERRCODE='40001';
            END IF;
            -- Сам нативный ряд фиксируется и при отсутствии зеркала.
            coordinate:=jsonb_build_array(root_id,native->0,native->1,parent_id,fallback_image,
                encode(sha256(convert_to((graph-ARRAY['rows','reads'])::text,'UTF8')),'hex'));
        END IF;
        output_bytes:=output_bytes+octet_length(coordinate::text)+2;
        IF output_bytes>8388608 THEN
            RAISE EXCEPTION 'role move project copy receipt exceeds byte budget' USING ERRCODE='54000';
        END IF;
        sources:=array_append(sources,coordinate);
    END LOOP;
    RETURN jsonb_build_object('sha256',encode(sha256(convert_to(jsonb_build_array(direct->'source',to_jsonb(sources))::text,'UTF8')),'hex'),
        'rows',used_rows,'reads',used_reads);
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'project match census source is being written' USING ERRCODE='40001';
END;
$matches$;

-- Полный набор аккаунтов и рёбер фиксируется на часах подготовки. Финальные
-- часы могут убрать поддержку истёкшей выдачи, но сохраняют исходный охват.
CREATE FUNCTION kaname._authority_role_move_bound_project_census_v1(
    p_role jsonb,p_moves jsonb,p_holders jsonb,p_copies jsonb,p_expected jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $bound_projects$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    prepared_holders jsonb:=p_holders;
    owner_plan jsonb;
    accounts jsonb;
    account_id text;
    reverse_edges jsonb;
    edge_sources jsonb[]:=ARRAY[]::jsonb[];
    project_batches jsonb[]:=ARRAY[]::jsonb[];
    source jsonb;
    projects jsonb;
    matches jsonb;
    used_rows integer;
    used_reads integer:=1;
    bytes bigint:=2;
    batch_rows integer;
BEGIN
    IF coalesce(proof->>'nonce','')='' OR jsonb_typeof(p_holders) IS DISTINCT FROM 'object'
        OR jsonb_typeof(p_copies) IS DISTINCT FROM 'array'
        OR (p_expected IS NOT NULL AND (jsonb_typeof(p_expected) IS DISTINCT FROM 'object'
            OR jsonb_typeof(p_expected->'holders') IS DISTINCT FROM 'object'
            OR jsonb_typeof(p_expected->'accounts') IS DISTINCT FROM 'object'
            OR jsonb_typeof(p_expected->'edges') IS DISTINCT FROM 'object'
            OR jsonb_typeof(p_expected->'matches_sha256') IS DISTINCT FROM 'string')) THEN
        RAISE EXCEPTION 'invalid bound project copy census input' USING ERRCODE='42501';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096
        OR octet_length(p_expected::text)>8388608 THEN
        RAISE EXCEPTION 'bound project census exceeds input budget' USING ERRCODE='54000';
    END IF;
    owner_plan:=kaname._authority_role_move_project_moved_owner_plan_v1(p_role,p_moves,p_rows);
    used_rows:=(owner_plan->>'rows')::integer;
    IF owner_plan->'predicates'='[]'::jsonb THEN
        IF p_expected IS NOT NULL THEN
            RAISE EXCEPTION 'held bound project positions disappeared' USING ERRCODE='40001';
        END IF;
        RETURN jsonb_build_object('source',NULL,'rows',used_rows,'reads',used_reads);
    END IF;
    IF p_expected IS NOT NULL THEN
        prepared_holders:=p_expected->'holders';
        IF p_holders='{}'::jsonb OR NOT (prepared_holders @> p_holders) THEN
            RAISE EXCEPTION 'bound project holder mode changed since preparation' USING ERRCODE='40001';
        END IF;
    END IF;
    IF prepared_holders='{}'::jsonb THEN
        RETURN jsonb_build_object('source',NULL,'rows',used_rows,'reads',used_reads);
    END IF;
    accounts:=kaname._authority_role_move_project_bound_accounts_v1(
        owner_plan->'predicates',prepared_holders,p_expected->'accounts',p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(accounts->>'rows')::integer;
    used_reads:=used_reads+(accounts->>'reads')::integer;
    FOR account_id IN SELECT value FROM jsonb_array_elements_text(accounts->'account_ids') LOOP
        IF p_expected IS NOT NULL AND jsonb_typeof(p_expected->'edges'->account_id) IS DISTINCT FROM 'object' THEN
            RAISE EXCEPTION 'held bound project edge receipt missing' USING ERRCODE='40001';
        END IF;
        reverse_edges:=kaname._authority_role_move_project_reverse_edges_v1(
            account_id,p_expected->'edges'->account_id,p_rows-used_rows,p_reads-used_reads);
        used_rows:=used_rows+(reverse_edges->>'rows')::integer;
        used_reads:=used_reads+(reverse_edges->>'reads')::integer;
        batch_rows:=1+jsonb_array_length(reverse_edges->'candidate_ids');
        IF batch_rows>p_rows-used_rows THEN
            RAISE EXCEPTION 'bound project union exceeds budget' USING ERRCODE='54000';
        END IF;
        used_rows:=used_rows+batch_rows;
        bytes:=bytes+octet_length(reverse_edges::text)+octet_length(account_id)+2;
        IF bytes>8388608 THEN
            RAISE EXCEPTION 'bound project edge receipts exceed byte budget' USING ERRCODE='54000';
        END IF;
        edge_sources:=array_append(edge_sources,jsonb_build_array(account_id,reverse_edges->'source'));
        project_batches:=array_append(project_batches,reverse_edges->'candidate_ids');
    END LOOP;
    SELECT coalesce(jsonb_agg(id ORDER BY id COLLATE "C"),'[]'::jsonb) INTO projects
        FROM (SELECT DISTINCT id COLLATE "C" AS id FROM unnest(project_batches) batch
              CROSS JOIN LATERAL jsonb_array_elements_text(batch) p(id)) union_projects;
    matches:=kaname._authority_role_move_project_census_matches_v1(
        p_role,p_moves,projects,prepared_holders,p_holders,false,p_expected IS NOT NULL,
        p_copies,p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(matches->>'rows')::integer;
    used_reads:=used_reads+(matches->>'reads')::integer;
    SELECT jsonb_build_object('holders',prepared_holders,'accounts',accounts->'source',
        'edges',coalesce(jsonb_object_agg(item->>0,item->1),'{}'::jsonb),'matches_sha256',matches->'sha256')
        INTO source FROM unnest(edge_sources) item;
    IF octet_length(source::text)>8388608 THEN
        RAISE EXCEPTION 'bound project census receipt exceeds byte budget' USING ERRCODE='54000';
    END IF;
    IF p_expected IS NOT NULL AND source IS DISTINCT FROM p_expected THEN
        RAISE EXCEPTION 'bound project census changed after preparation' USING ERRCODE='40001';
    END IF;
    RETURN jsonb_build_object('source',source,'rows',used_rows,'reads',used_reads);
END;
$bound_projects$;

-- Для области определения список прежних копий выводится из физических
-- источников аккаунта или проекта, даже если Go не предложил копий.
CREATE FUNCTION kaname._authority_role_move_definition_project_census_v1(
    p_role jsonb,p_moves jsonb,p_copies jsonb,p_expected jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $definition$
DECLARE
    scope_account_id text:=nullif(p_role->>'account_id','');
    definition_project_id text:=nullif(p_role->>'project_id','');
    definition_project jsonb;
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    forbidden constant text:=U&'[:#*\0001-\0020\007F-\00A0\1680\2000-\200A\2028\2029\202F\205F\3000]';
    parent_account jsonb;
    owner_plan jsonb;
    predicate jsonb;
    selected_owner boolean:=false;
    reverse_edges jsonb;
    matches jsonb;
    source jsonb;
    used_rows integer;
    used_reads integer:=1;
BEGIN
    IF (scope_account_id IS NULL)=(definition_project_id IS NULL)
        OR octet_length(scope_account_id)>16384 OR scope_account_id COLLATE "C" ~ forbidden
        OR octet_length(definition_project_id)>16384 OR definition_project_id COLLATE "C" ~ forbidden
        OR p_role->'is_system' IS DISTINCT FROM 'false'::jsonb
        OR coalesce(p_role->>'cluster_id','')<>''
        OR coalesce(p_role->>'owner_module','')<>'' OR p_role->'live' IS DISTINCT FROM 'true'::jsonb
        OR jsonb_typeof(p_moves) IS DISTINCT FROM 'array'
        OR jsonb_typeof(p_copies) IS DISTINCT FROM 'array'
        OR (p_expected IS NOT NULL AND (jsonb_typeof(p_expected) IS DISTINCT FROM 'object'
            OR coalesce(jsonb_typeof(p_expected->'reverse_edges'),'') NOT IN ('object','null')
            OR jsonb_typeof(p_expected->'account') IS DISTINCT FROM 'array'
            OR p_expected->>'matches_sha256' IS NULL)) THEN
        RAISE EXCEPTION 'invalid definition project copy census' USING ERRCODE='42501';
    END IF;
    used_rows:=jsonb_array_length(p_moves);
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096
        OR octet_length(p_copies::text)>8388608 THEN
        RAISE EXCEPTION 'definition project copy census exceeds budget' USING ERRCODE='54000';
    END IF;
    owner_plan:=kaname._authority_role_move_project_moved_owner_plan_v1(p_role,p_moves,p_rows);
    used_rows:=(owner_plan->>'rows')::integer;
    IF owner_plan->'predicates'='[]'::jsonb THEN
        IF p_expected IS NOT NULL THEN
            RAISE EXCEPTION 'definition project copy positions changed' USING ERRCODE='40001';
        END IF;
        RETURN jsonb_build_object('source',NULL,'rows',used_rows,'reads',used_reads);
    END IF;

    IF p_rows-used_rows<5 OR p_reads-used_reads<5 THEN
        RAISE EXCEPTION 'definition account custody exceeds budget' USING ERRCODE='54000';
    END IF;
    -- Тот же порядок оград, что у переписи и у подтверждения отдельного проекта.
    IF p_expected IS NULL THEN
        LOCK TABLE ONLY kaname.catalog_resource, ONLY kaname.resource_mirror, ONLY kaname.resource_parent_edge
            IN SHARE MODE NOWAIT;
    END IF;
    IF EXISTS(SELECT FROM unnest(ARRAY['kaname.accounts'::regclass,'kaname.projects'::regclass]) rel(oid)
        WHERE NOT EXISTS(SELECT FROM pg_class c WHERE c.oid=rel.oid AND c.relowner=current_user::regrole
            AND c.relkind='r' AND c.relpersistence='p'
            AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relispartition OR c.relhasrules)
            AND NOT EXISTS(SELECT FROM pg_inherits h WHERE h.inhparent=c.oid OR h.inhrelid=c.oid)
            AND has_table_privilege((proof->>'invoker_oid')::oid,c.oid,'SELECT')
            AND EXISTS(SELECT FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid
                JOIN pg_am am ON am.oid=idx.relam
                JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=i.indkey[0] AND a.attname='id'
                WHERE i.indrelid=c.oid AND i.indnkeyatts=1 AND am.amname='btree'
                    AND i.indisunique AND i.indisvalid AND i.indisready AND i.indimmediate
                    AND i.indpred IS NULL AND i.indexprs IS NULL))) THEN
        RAISE EXCEPTION 'definition account or project custody differs' USING ERRCODE='42501';
    END IF;
    IF definition_project_id IS NOT NULL THEN
        IF p_rows-used_rows<6 OR p_reads-used_reads<6 THEN
            RAISE EXCEPTION 'definition project identity exceeds budget' USING ERRCODE='54000';
        END IF;
        SELECT jsonb_build_array(p.xmin::text,p.ctid::text,p.id,p.account_id) INTO definition_project
          FROM ONLY kaname.projects p WHERE p.id=definition_project_id FOR SHARE OF p NOWAIT;
        scope_account_id:=definition_project->>3;
        IF coalesce(scope_account_id,'')='' OR octet_length(scope_account_id)>16384
            OR scope_account_id COLLATE "C" ~ forbidden THEN
            RAISE EXCEPTION 'definition project or its owner account is missing' USING ERRCODE='40001';
        END IF;
        used_rows:=used_rows+1;
        used_reads:=used_reads+1;
    END IF;
    IF p_expected IS NOT NULL AND p_expected->'definition_project' IS DISTINCT FROM coalesce(definition_project,'null'::jsonb) THEN
        RAISE EXCEPTION 'definition project identity changed after preparation' USING ERRCODE='40001';
    END IF;
    SELECT jsonb_build_array(a.xmin::text,a.ctid::text,a.id,a.labels,a.access_labels) INTO parent_account
      FROM ONLY kaname.accounts a WHERE a.id=scope_account_id FOR SHARE OF a NOWAIT;
    IF parent_account IS NULL OR jsonb_typeof(parent_account->3) IS DISTINCT FROM 'object'
        OR kaname.access_labels_valid_v1(parent_account->4) IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'definition account source missing or invalid' USING ERRCODE='40001';
    END IF;
    IF octet_length(parent_account::text)>8388608 THEN
        RAISE EXCEPTION 'definition account source exceeds byte budget' USING ERRCODE='54000';
    END IF;
    IF p_expected IS NOT NULL AND p_expected->'account' IS DISTINCT FROM parent_account THEN
        RAISE EXCEPTION 'definition account source changed after preparation' USING ERRCODE='40001';
    END IF;
    used_rows:=used_rows+5;
    used_reads:=used_reads+5;
    -- Контейнер выбирается до обхода рёбер. Неподходящая область может
    -- иметь большую перепись, но она не участвует в операции переноса.
    FOR predicate IN SELECT value FROM jsonb_array_elements(owner_plan->'predicates') WHERE definition_project_id IS NULL LOOP
        IF kaname._authority_resource_selector_matches_v3(predicate,'iam.account',scope_account_id,
            parent_account->3,parent_account->4) THEN
            selected_owner:=true;
            EXIT;
        END IF;
    END LOOP;
    IF NOT selected_owner THEN
        matches:=kaname._authority_role_move_project_census_matches_v1(
            p_role,p_moves,'[]'::jsonb,'{}'::jsonb,'{}'::jsonb,true,p_expected IS NOT NULL,
            p_copies,p_rows-used_rows,p_reads-used_reads);
        used_rows:=used_rows+(matches->>'rows')::integer;
        used_reads:=used_reads+(matches->>'reads')::integer;
        source:=jsonb_build_object('account',parent_account,'definition_project',definition_project,'reverse_edges',NULL,'matches_sha256',matches->'sha256');
        IF p_expected IS NOT NULL AND source IS DISTINCT FROM p_expected THEN
            RAISE EXCEPTION 'definition account predicate changed after preparation' USING ERRCODE='40001';
        END IF;
        RETURN jsonb_build_object('source',source,'rows',used_rows,'reads',used_reads);
    END IF;

    IF p_expected IS NOT NULL AND jsonb_typeof(p_expected->'reverse_edges') IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'definition account reverse scope changed after preparation' USING ERRCODE='40001';
    END IF;
    reverse_edges:=kaname._authority_role_move_project_reverse_edges_v1(
        scope_account_id,nullif(p_expected->'reverse_edges','null'::jsonb),p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(reverse_edges->>'rows')::integer;
    used_reads:=used_reads+(reverse_edges->>'reads')::integer;
    matches:=kaname._authority_role_move_project_census_matches_v1(
        p_role,p_moves,reverse_edges->'candidate_ids','{}'::jsonb,'{}'::jsonb,true,p_expected IS NOT NULL,
        p_copies,p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(matches->>'rows')::integer;
    used_reads:=used_reads+(matches->>'reads')::integer;
    source:=jsonb_build_object('account',parent_account,'definition_project',definition_project,'reverse_edges',reverse_edges->'source',
        'matches_sha256',matches->'sha256');
    IF p_expected IS NOT NULL AND source IS DISTINCT FROM p_expected THEN
        RAISE EXCEPTION 'definition project copy census changed after preparation' USING ERRCODE='40001';
    END IF;
    RETURN jsonb_build_object('source',source,'rows',used_rows,'reads',used_reads);
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'definition project copy source is being written' USING ERRCODE='40001';
END;
$definition$;

-- Для проекта квитанция зеркала разрешает только подтверждённые OLD-пары.
CREATE FUNCTION kaname._authority_role_move_iam_copy_sources_hold_v2(
    p_root_type text,p_root_id text,p_expected jsonb,p_access_labels jsonb,p_project_source jsonb,
    p_actor_type text,p_actor_id text,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $native$
DECLARE
    table_name text;
    resource_kind text;
    physical jsonb;
    old_row jsonb;
    old_access jsonb;
    source_pairs jsonb:='{}'::jsonb;
    proof jsonb;
    definitions jsonb;
    sources jsonb;
    used_rows integer:=1;
    used_reads integer:=1;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF current_setting('transaction_isolation') IS DISTINCT FROM 'read committed' THEN
        RAISE EXCEPTION 'copy source capture requires READ COMMITTED' USING ERRCODE='25001';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN
        RAISE EXCEPTION 'copy source capture budget exhausted' USING ERRCODE='54000';
    END IF;
    SELECT t.rel,t.kind INTO table_name,resource_kind FROM (VALUES
        ('iam.account','accounts','account'),
        ('iam.project','projects','project'),
        ('iam.serviceAccount','service_accounts','service_account')
    ) t(dotted,rel,kind) WHERE t.dotted=p_root_type;
    IF table_name IS NULL OR coalesce(p_root_id,'')=''
        OR jsonb_typeof(p_expected) IS DISTINCT FROM 'array'
        OR kaname.access_labels_valid_v1(p_access_labels) IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'invalid IAM copy root or proposed access labels' USING ERRCODE='42501';
    END IF;

    EXECUTE format('SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r))
        FROM ONLY kaname.%I r WHERE r.id=$1 FOR UPDATE OF r NOWAIT',table_name)
        INTO physical USING p_root_id;
    IF physical IS NULL OR physical IS DISTINCT FROM p_expected THEN
        RAISE EXCEPTION 'IAM copy root changed before capture' USING ERRCODE='40001';
    END IF;
    old_row:=physical->2;
    old_access:=old_row->'access_labels';
    IF kaname.access_labels_valid_v1(old_access) IS DISTINCT FROM true
        OR jsonb_typeof(old_row->'labels') IS DISTINCT FROM 'object'
        OR NOT (p_access_labels @> old_access) OR p_access_labels=old_access THEN
        RAISE EXCEPTION 'IAM selector move must only add protected copies' USING ERRCODE='42501';
    END IF;
    used_rows:=used_rows+(SELECT count(*) FROM jsonb_object_keys(p_access_labels));
    IF used_rows>p_rows THEN
        RAISE EXCEPTION 'copy source capture budget exhausted' USING ERRCODE='54000';
    END IF;
    IF p_project_source IS NOT NULL THEN
        proof:=kaname._authority_role_move_attestation_v1();
        IF p_root_type IS DISTINCT FROM 'iam.project'
            OR p_project_source#>>'{graph,project_id}' IS DISTINCT FROM p_root_id
            OR p_project_source#>'{graph,native}' IS DISTINCT FROM p_expected
            OR p_project_source#>>'{graph,nonce}' IS DISTINCT FROM proof->>'nonce'
            OR p_project_source#>>'{graph,backend_pid}' IS DISTINCT FROM pg_backend_pid()::text
            OR p_project_source#>>'{graph,txid}' IS DISTINCT FROM pg_current_xact_id_if_assigned()::text
            OR kaname.access_labels_valid_v1(p_project_source->'pairs') IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'invalid held nonnative project copy source' USING ERRCODE='42501';
        END IF;
        source_pairs:=p_project_source->'pairs';
    END IF;
    IF EXISTS (SELECT FROM jsonb_each(p_access_labels) n
        WHERE NOT (old_access ? n.key) AND n.value IS DISTINCT FROM (old_row->'labels'->n.key)
          AND n.value IS DISTINCT FROM source_pairs->n.key) THEN
        RAISE EXCEPTION 'protected copy differs from the physical ordinary label' USING ERRCODE='42501';
    END IF;

    used_rows:=used_rows+2;
    used_reads:=used_reads+2;
    IF used_rows>p_rows OR used_reads>p_reads THEN
        RAISE EXCEPTION 'copy source capture budget exhausted' USING ERRCODE='54000';
    END IF;
    PERFORM kaname._authority_role_move_copy_registry_hold_v1();
    definitions:=kaname._authority_resource_access_label_requirements_v1(resource_kind,
        old_row,jsonb_set(old_row,'{access_labels}',p_access_labels),p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(definitions->>'rows')::integer;
    used_reads:=used_reads+(definitions->>'reads')::integer;
    sources:=kaname._authority_resource_access_label_sources_hold_v1(p_actor_type,p_actor_id,
        definitions->'requirements',p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(sources->>'rows')::integer;
    used_reads:=used_reads+(sources->>'reads')::integer;
    IF used_rows IS NULL OR used_rows>p_rows OR used_reads IS NULL OR used_reads>p_reads THEN
        RAISE EXCEPTION 'copy source capture budget exhausted' USING ERRCODE='54000';
    END IF;
    RETURN jsonb_build_object('root_type',p_root_type,'root_id',p_root_id,'physical',physical,
        'new_access_labels',p_access_labels,'requirements',definitions->'requirements','authority',sources,
        'rows',used_rows,'reads',used_reads)
        ||CASE WHEN p_project_source IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('project_source',p_project_source) END;
END;
$native$;

DO $private$
DECLARE
    grantee record;
    signature text;
BEGIN
    FOREACH signature IN ARRAY ARRAY['kaname._authority_role_move_project_copy_support_v1(jsonb,jsonb,jsonb,boolean,jsonb,integer)','kaname._authority_role_move_project_copy_pairs_v1(jsonb,jsonb,integer)','kaname._authority_role_move_project_copy_plan_hold_v1(jsonb,jsonb,jsonb,jsonb,integer,integer)','kaname._authority_role_move_project_copy_plan_require_v1(jsonb,jsonb,jsonb,integer,integer)','kaname._authority_role_move_project_reverse_edges_v1(text,jsonb,integer,integer)','kaname._authority_role_move_project_moved_owner_plan_v1(jsonb,jsonb,integer)','kaname._authority_role_move_project_container_scopes_v1(jsonb,integer)','kaname._authority_role_move_project_bound_accounts_v1(jsonb,jsonb,jsonb,integer,integer)','kaname._authority_role_move_project_direct_census_v1(jsonb,jsonb,jsonb,jsonb,boolean,boolean,integer,integer)','kaname._authority_role_move_project_census_matches_v1(jsonb,jsonb,jsonb,jsonb,jsonb,boolean,boolean,jsonb,integer,integer)','kaname._authority_role_move_bound_project_census_v1(jsonb,jsonb,jsonb,jsonb,jsonb,integer,integer)','kaname._authority_role_move_definition_project_census_v1(jsonb,jsonb,jsonb,jsonb,integer,integer)','kaname._authority_role_move_iam_copy_sources_hold_v2(text,text,jsonb,jsonb,jsonb,text,text,integer,integer)'] LOOP
        FOR grantee IN
            SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
            WHERE p.oid=to_regprocedure(signature) AND a.grantee<>p.proowner
        LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',signature,
                CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
        END LOOP;
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $scope_install$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('_authority_role_move_iam_copy_sources_hold_v1(text,text,jsonb,jsonb,text,text,integer,integer)','99c34be6e35ca9b1b1b97ea0c16f6c1b4768c3c000d3613136ac9f1f9a5cdbea','3a04707b697d8afeb8a90b10bd59b5c488e5a7e0c385c47b0e8ee48752720a87',$changes$[
 [
  "\nDECLARE\n    table_name text;\n    resource_kind text;\n    physical jsonb;\n    old_row jsonb;\n    old_access jsonb;\n    definitions jsonb;\n    sources jsonb;\n    used_rows integer:=1;\n    used_reads integer:=1;\nBEGIN\n    PERFORM kaname.authority_protocol_require_owner();\n    IF current_setting('transaction_isolation') IS DISTINCT FROM 'read committed' THEN\n        RAISE EXCEPTION 'copy source capture requires READ COMMITTED' USING ERRCODE='25001';\n    END IF;\n    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000\n        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN\n        RAISE EXCEPTION 'copy source capture budget exhausted' USING ERRCODE='54000';\n    END IF;\n    SELECT t.rel,t.kind INTO table_name,resource_kind FROM (VALUES\n        ('iam.account','accounts','account'),\n        ('iam.project','projects','project'),\n        ('iam.serviceAccount','service_accounts','service_account')\n    ) t(dotted,rel,kind) WHERE t.dotted=p_root_type;\n    IF table_name IS NULL OR coalesce(p_root_id,'')=''\n        OR jsonb_typeof(p_expected) IS DISTINCT FROM 'array'\n        OR kaname.access_labels_valid_v1(p_access_labels) IS DISTINCT FROM true THEN\n        RAISE EXCEPTION 'invalid IAM copy root or proposed access labels' USING ERRCODE='42501';\n    END IF;\n\n    EXECUTE format('SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r))\n        FROM ONLY kaname.%I r WHERE r.id=$1 FOR UPDATE OF r NOWAIT',table_name)\n        INTO physical USING p_root_id;\n    IF physical IS NULL OR physical IS DISTINCT FROM p_expected THEN\n        RAISE EXCEPTION 'IAM copy root changed before capture' USING ERRCODE='40001';\n    END IF;\n    old_row:=physical->2;\n    old_access:=old_row->'access_labels';\n    IF kaname.access_labels_valid_v1(old_access) IS DISTINCT FROM true\n        OR jsonb_typeof(old_row->'labels') IS DISTINCT FROM 'object'\n        OR NOT (p_access_labels @> old_access) OR p_access_labels=old_access THEN\n        RAISE EXCEPTION 'IAM selector move must only add protected copies' USING ERRCODE='42501';\n    END IF;\n    used_rows:=used_rows+(SELECT count(*) FROM jsonb_object_keys(p_access_labels));\n    IF used_rows>p_rows THEN\n        RAISE EXCEPTION 'copy source capture budget exhausted' USING ERRCODE='54000';\n    END IF;\n    IF EXISTS (SELECT FROM jsonb_each(p_access_labels) n\n        WHERE NOT (old_access ? n.key) AND n.value IS DISTINCT FROM (old_row->'labels'->n.key)) THEN\n        RAISE EXCEPTION 'protected copy differs from the physical ordinary label' USING ERRCODE='42501';\n    END IF;\n\n    used_rows:=used_rows+2;\n    used_reads:=used_reads+2;\n    IF used_rows>p_rows OR used_reads>p_reads THEN\n        RAISE EXCEPTION 'copy source capture budget exhausted' USING ERRCODE='54000';\n    END IF;\n    PERFORM kaname._authority_role_move_copy_registry_hold_v1();\n    definitions:=kaname._authority_resource_access_label_requirements_v1(resource_kind,\n        old_row,jsonb_set(old_row,'{access_labels}',p_access_labels),p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(definitions->>'rows')::integer;\n    used_reads:=used_reads+(definitions->>'reads')::integer;\n    sources:=kaname._authority_resource_access_label_sources_hold_v1(p_actor_type,p_actor_id,\n        definitions->'requirements',p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(sources->>'rows')::integer;\n    used_reads:=used_reads+(sources->>'reads')::integer;\n    IF used_rows IS NULL OR used_rows>p_rows OR used_reads IS NULL OR used_reads>p_reads THEN\n        RAISE EXCEPTION 'copy source capture budget exhausted' USING ERRCODE='54000';\n    END IF;\n    RETURN jsonb_build_object('root_type',p_root_type,'root_id',p_root_id,'physical',physical,\n        'new_access_labels',p_access_labels,'requirements',definitions->'requirements','authority',sources,\n        'rows',used_rows,'reads',used_reads);\nEND;\n",
  "\nBEGIN\n    RETURN kaname._authority_role_move_iam_copy_sources_hold_v2(p_root_type,p_root_id,p_expected,p_access_labels,\n        NULL,p_actor_type,p_actor_id,p_rows,p_reads);\nEND;\n"
 ]
]$changes$::jsonb),
  ('_authority_role_move_copy_requirements_hold_v1(jsonb,text,text,integer,integer)','3ad9612a52ef6d3d615c94439e62dfb7a1da6d545cec876867389a718cba4576','048d1168e4f57413c03a850a2cfab860a2d76f8ee1d7bb5a3900de43c8930d36',$changes$[
 [
  "root-ARRAY['root_type','root_id','physical','new_access_labels']",
  "root-ARRAY['root_type','root_id','physical','new_access_labels','project_source']"
 ],
 [
  "        IF root_type IN ('iam.account','iam.project','iam.serviceAccount') THEN",
  "        IF root ? 'project_source' THEN\n            held:=kaname._authority_role_move_iam_copy_sources_hold_v2(root_type,root_id,\n                root->'physical',root->'new_access_labels',root->'project_source',p_actor_type,p_actor_id,\n                p_rows-used_rows,p_reads-used_reads);\n        ELSIF root_type IN ('iam.account','iam.project','iam.serviceAccount') THEN"
 ]
]$changes$::jsonb),
  ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','8fe4c3a1e587d9f09db5bd5e7a73df6795166457f57badf53087e1dd0107dd62','780972ca904bcf3d09f504fa405b4e375f58c2fc7cfc026708df286059ec589c',$changes$[
 [
  "    eligible jsonb;",
  "    eligible jsonb;\n    prepared_plan jsonb;\n    project_hold jsonb;\n    definition_projects jsonb;\n    bound_projects jsonb;"
 ],
 [
  "    copies:=kaname._authority_role_move_copy_requirements_hold_v1(p_input->'copy_candidates',",
  "    prepared_plan:=p_input->'copy_candidates';\n    IF jsonb_path_exists(prepared_plan,'$[*].project_source') THEN\n        eligible:=kaname._authority_role_move_binding_new_v1(\n            jsonb_build_object('role_id',p_input->>'role_id','role',role_image,'binding_census',carriers->'old'),\n            carriers->'binding_status',p_rows-used_rows);\n        used_rows:=used_rows+(eligible->>'rows')::integer;\n        project_hold:=kaname._authority_role_move_project_copy_plan_hold_v1(prepared_plan,role_image#>'{physical,2}',\n            p_input->'moves',eligible->'holders',p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(project_hold->>'rows')::integer;\n        used_reads:=used_reads+(project_hold->>'reads')::integer;\n        prepared_plan:=project_hold->'plan';\n    END IF;\n    copies:=kaname._authority_role_move_copy_requirements_hold_v1(prepared_plan,"
 ],
 [
  "    IF selector_source IS NULL THEN",
  "    IF carriers->'old'='{\"bindings\":[],\"subjects\":[],\"members\":[],\"ledger\":[]}'::jsonb\n        AND (coalesce(role_image#>>'{physical,2,account_id}','')<>'' OR coalesce(role_image#>>'{physical,2,project_id}','')<>'') THEN\n        definition_projects:=kaname._authority_role_move_definition_project_census_v1(\n            role_image#>'{physical,2}',p_input->'moves',prepared_plan,NULL,p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(definition_projects->>'rows')::integer;\n        used_reads:=used_reads+(definition_projects->>'reads')::integer;\n        IF definition_projects->'source'<>'null'::jsonb THEN\n            frozen:=frozen||jsonb_build_object('definition_project_copy',jsonb_build_object(\n                'moves',p_input->'moves','source',definition_projects->'source'));\n        END IF;\n    END IF;\n    IF selector_source IS NULL THEN"
 ],
 [
  "        eligible:=kaname._authority_role_move_binding_new_v1(frozen,carriers->'binding_status',p_rows-used_rows);\n        used_rows:=used_rows+(eligible->>'rows')::integer;",
  "        IF eligible IS NULL THEN\n            eligible:=kaname._authority_role_move_binding_new_v1(frozen,carriers->'binding_status',p_rows-used_rows);\n            used_rows:=used_rows+(eligible->>'rows')::integer;\n        END IF;\n        bound_projects:=kaname._authority_role_move_bound_project_census_v1(\n            role_image#>'{physical,2}',p_input->'moves',eligible->'holders',prepared_plan,NULL,p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(bound_projects->>'rows')::integer;\n        used_reads:=used_reads+(bound_projects->>'reads')::integer;\n        IF bound_projects->'source'<>'null'::jsonb THEN\n            frozen:=frozen||jsonb_build_object('bound_project_copy',jsonb_build_object(\n                'moves',p_input->'moves','source',bound_projects->'source'));\n        END IF;"
 ]
]$changes$::jsonb),
  ('_authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)','8818e245bf1517db88a091c9bbb9b950da510eaa50db01f685a6772e49d68e27','de4d128e08cb26f3762f97f89953459ba1c7037e16b070c647eb87eb180ea1e2',$changes$[
 [
  "    binding_new jsonb;",
  "    binding_new jsonb;\n    held_project_cost jsonb;\n    definition_projects jsonb;\n    bound_projects jsonb;"
 ],
 [
  "    predicates:=kaname._authority_role_move_predicate_plan_v1",
  "    IF p_frozen ? 'definition_project_copy' THEN\n        IF p_frozen->'binding_census' IS DISTINCT FROM '{\"bindings\":[],\"subjects\":[],\"members\":[],\"ledger\":[]}'::jsonb\n            OR binding_new->'holders' IS DISTINCT FROM '{}'::jsonb THEN\n            RAISE EXCEPTION 'held definition project copy has binding carriers' USING ERRCODE='40001';\n        END IF;\n        definition_projects:=kaname._authority_role_move_definition_project_census_v1(\n            actual_role_row->2,p_frozen#>'{definition_project_copy,moves}',p_copies,\n            p_frozen#>'{definition_project_copy,source}',p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(definition_projects->>'rows')::integer;\n        used_reads:=used_reads+(definition_projects->>'reads')::integer;\n    END IF;\n    IF p_frozen ? 'bound_project_copy' THEN\n        bound_projects:=kaname._authority_role_move_bound_project_census_v1(\n            actual_role_row->2,p_frozen#>'{bound_project_copy,moves}',binding_new->'holders',p_copies,\n            p_frozen#>'{bound_project_copy,source}',p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(bound_projects->>'rows')::integer;\n        used_reads:=used_reads+(bound_projects->>'reads')::integer;\n    END IF;\n    predicates:=kaname._authority_role_move_predicate_plan_v1"
 ],
 [
  "    result:=kaname._authority_role_move_copy_requirements_require_v1",
  "    IF jsonb_path_exists(p_frozen#>'{copies,roots}','$.*.project_source') THEN\n        held_project_cost:=kaname._authority_role_move_project_copy_plan_require_v1(\n            p_frozen#>'{copies,roots}',p_copies,binding_new->'holders',p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(held_project_cost->>'rows')::integer;\n        used_reads:=used_reads+(held_project_cost->>'reads')::integer;\n    END IF;\n    result:=kaname._authority_role_move_copy_requirements_require_v1"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','a3b988f9e0ea9b33843c53062788a37f859bd4a9d5d1c7effbd4488d7cf0b3fe','49713a25044e6fc0aa577f2433e0a30cb34a252cd3015756ccafc0c09c00cbfa',$changes$[
 [
  "99c34be6e35ca9b1b1b97ea0c16f6c1b4768c3c000d3613136ac9f1f9a5cdbea",
  "3a04707b697d8afeb8a90b10bd59b5c488e5a7e0c385c47b0e8ee48752720a87"
 ],
 [
  "3ad9612a52ef6d3d615c94439e62dfb7a1da6d545cec876867389a718cba4576",
  "048d1168e4f57413c03a850a2cfab860a2d76f8ee1d7bb5a3900de43c8930d36"
 ],
 [
  "8fe4c3a1e587d9f09db5bd5e7a73df6795166457f57badf53087e1dd0107dd62",
  "780972ca904bcf3d09f504fa405b4e375f58c2fc7cfc026708df286059ec589c"
 ],
 [
  "8818e245bf1517db88a091c9bbb9b950da510eaa50db01f685a6772e49d68e27",
  "de4d128e08cb26f3762f97f89953459ba1c7037e16b070c647eb87eb180ea1e2"
 ],
 [
  " ('_authority_role_move_old_project_match_v1(jsonb,integer,integer,jsonb,jsonb,jsonb,jsonb,text,text)','7410529c62e5b4fb4e4fe5989ddab8135befa4d16a27b7e8fb38bb981d1969c3',false,'i',true,'private'),\n",
  " ('_authority_role_move_old_project_match_v1(jsonb,integer,integer,jsonb,jsonb,jsonb,jsonb,text,text)','7410529c62e5b4fb4e4fe5989ddab8135befa4d16a27b7e8fb38bb981d1969c3',false,'i',true,'private'),\n ('_authority_role_move_project_copy_support_v1(jsonb,jsonb,jsonb,boolean,jsonb,integer)','56e979a2a932e6756fd8b62378e7c31a68f8f802ac414065a797177cb4d92a9b',false,'i',true,'private'),\n ('_authority_role_move_project_copy_pairs_v1(jsonb,jsonb,integer)','9d631da8d3cd6cba9d14d8ccd2f4fd3b68f84c219bcc36e3b192258b58cbdc7c',false,'i',true,'private'),\n ('_authority_role_move_project_copy_plan_hold_v1(jsonb,jsonb,jsonb,jsonb,integer,integer)','c76c3b6bdbe79a656dd49e8da67b68b03b941236fb0e4eb9a23df2bb901bd447',false,'v',true,'private'),\n ('_authority_role_move_project_copy_plan_require_v1(jsonb,jsonb,jsonb,integer,integer)','791eeefcf8dfedd77f65e8bd3ef7bb129fdba21a0f2b8cea20ebd6a123038d3e',false,'v',true,'private'),\n ('_authority_role_move_project_reverse_edges_v1(text,jsonb,integer,integer)','67988d0eaacbc251f3d2baccab29aab3aed94de504ffbc79b3a3e288e872e4cc',false,'v',true,'private'),\n ('_authority_role_move_project_moved_owner_plan_v1(jsonb,jsonb,integer)','55c5b519f26151ade2c3c3bd12b25becce864e32ff3ab16ebe7cff43629b0e67',false,'i',true,'private'),\n ('_authority_role_move_project_container_scopes_v1(jsonb,integer)','12e258d400b23aac7aea899275b595f7e34b090094354e80fdf90333d08a31b6',false,'i',true,'private'),\n ('_authority_role_move_project_bound_accounts_v1(jsonb,jsonb,jsonb,integer,integer)','22b24ae00b4aa760a50760f49afc70583d6cd978bcca4478ed55a6af6037c0f0',false,'v',true,'private'),\n ('_authority_role_move_project_direct_census_v1(jsonb,jsonb,jsonb,jsonb,boolean,boolean,integer,integer)','bcde4a6ec83a5d788726740a3d1139574c9f94f0c60f2c8a1bd2aa54b940add4',false,'v',true,'private'),\n ('_authority_role_move_project_census_matches_v1(jsonb,jsonb,jsonb,jsonb,jsonb,boolean,boolean,jsonb,integer,integer)','c6ea8c541a2f88a211c8cb39c4598e446fb34a3d36b71f64bbf47cd200303b67',false,'v',true,'private'),\n ('_authority_role_move_bound_project_census_v1(jsonb,jsonb,jsonb,jsonb,jsonb,integer,integer)','f42af8290e412013bc61aecea021712a0683a95f0823b47ff9b35c4ac8b6c11d',false,'v',true,'private'),\n ('_authority_role_move_definition_project_census_v1(jsonb,jsonb,jsonb,jsonb,integer,integer)','ce16ca61fb0e4b91914d905e6040cd117a8c79c9c160d6bc86b7f1dac05ddcda',false,'v',true,'private'),\n ('_authority_role_move_iam_copy_sources_hold_v2(text,text,jsonb,jsonb,jsonb,text,text,integer,integer)','2a015c19d649511f7021d30a4626d5eb87f7b40b76e8c980b16eb922eba90e0e',false,'v',true,'private'),\n"
 ],
 [
  "  ('_authority_role_move_old_project_match_v1(jsonb,integer,integer,jsonb,jsonb,jsonb,jsonb,text,text)','jsonb',9,ARRAY['p_rules','p_rule_index','p_child_index','p_scope','p_target','p_account','p_mirror','p_project_id','p_mirror_account_id']),\n",
  "  ('_authority_role_move_old_project_match_v1(jsonb,integer,integer,jsonb,jsonb,jsonb,jsonb,text,text)','jsonb',9,ARRAY['p_rules','p_rule_index','p_child_index','p_scope','p_target','p_account','p_mirror','p_project_id','p_mirror_account_id']),\n  ('_authority_role_move_project_copy_support_v1(jsonb,jsonb,jsonb,boolean,jsonb,integer)','jsonb',6,ARRAY['p_graph_receipt','p_role','p_moves','p_definition','p_holders','p_rows']),\n  ('_authority_role_move_project_copy_pairs_v1(jsonb,jsonb,integer)','jsonb',3,ARRAY['p_source','p_holders','p_rows']),\n  ('_authority_role_move_project_copy_plan_hold_v1(jsonb,jsonb,jsonb,jsonb,integer,integer)','jsonb',6,ARRAY['p_plan','p_role','p_moves','p_holders','p_rows','p_reads']),\n  ('_authority_role_move_project_copy_plan_require_v1(jsonb,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_plan','p_copies','p_holders','p_rows','p_reads']),\n  ('_authority_role_move_project_reverse_edges_v1(text,jsonb,integer,integer)','jsonb',4,ARRAY['p_scope_id','p_expected','p_rows','p_reads']),\n  ('_authority_role_move_project_moved_owner_plan_v1(jsonb,jsonb,integer)','jsonb',3,ARRAY['p_role','p_moves','p_rows']),\n  ('_authority_role_move_project_container_scopes_v1(jsonb,integer)','jsonb',2,ARRAY['p_holders','p_rows']),\n  ('_authority_role_move_project_bound_accounts_v1(jsonb,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_predicates','p_holders','p_expected','p_rows','p_reads']),\n  ('_authority_role_move_project_direct_census_v1(jsonb,jsonb,jsonb,jsonb,boolean,boolean,integer,integer)','jsonb',8,ARRAY['p_role','p_moves','p_prepared_holders','p_holders','p_definition','p_replay','p_rows','p_reads']),\n  ('_authority_role_move_project_census_matches_v1(jsonb,jsonb,jsonb,jsonb,jsonb,boolean,boolean,jsonb,integer,integer)','jsonb',10,ARRAY['p_role','p_moves','p_project_ids','p_prepared_holders','p_holders','p_definition','p_replay','p_copies','p_rows','p_reads']),\n  ('_authority_role_move_bound_project_census_v1(jsonb,jsonb,jsonb,jsonb,jsonb,integer,integer)','jsonb',7,ARRAY['p_role','p_moves','p_holders','p_copies','p_expected','p_rows','p_reads']),\n  ('_authority_role_move_definition_project_census_v1(jsonb,jsonb,jsonb,jsonb,integer,integer)','jsonb',6,ARRAY['p_role','p_moves','p_copies','p_expected','p_rows','p_reads']),\n  ('_authority_role_move_iam_copy_sources_hold_v2(text,text,jsonb,jsonb,jsonb,text,text,integer,integer)','jsonb',9,ARRAY['p_root_type','p_root_id','p_expected','p_access_labels','p_project_source','p_actor_type','p_actor_id','p_rows','p_reads']),\n"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','6887f5816495ae2a898600a48e57ca2d7bcf8c2a94c64daeefda497752365f45','d03bfd87fb04ec3da910fb119b13d2061dd248316e799a317cae3bdf53d39629',$changes$[
 [
  "a3b988f9e0ea9b33843c53062788a37f859bd4a9d5d1c7effbd4488d7cf0b3fe",
  "49713a25044e6fc0aa577f2433e0a30cb34a252cd3015756ccafc0c09c00cbfa"
 ]
]$changes$::jsonb),
  ('authority_metadata_service_account_access_label_ready_v1()','a1bdb56d1e1124945c6463490415027d3524497d6d077589cb44c4e249df4592','cc3e2aff7e31c47fa51bc7a63e29d98c5b40759b4b1d1f6e86dcec6b85c58472',$changes$[
 [
  "a3b988f9e0ea9b33843c53062788a37f859bd4a9d5d1c7effbd4488d7cf0b3fe",
  "49713a25044e6fc0aa577f2433e0a30cb34a252cd3015756ccafc0c09c00cbfa"
 ],
 [
  "6887f5816495ae2a898600a48e57ca2d7bcf8c2a94c64daeefda497752365f45",
  "d03bfd87fb04ec3da910fb119b13d2061dd248316e799a317cae3bdf53d39629"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move project source custody predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move project source custody splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move project source custody body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move project source custody function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move project source custody function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move project source custody custody differs after migration' USING ERRCODE='55000';END IF;
END;
$scope_install$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $scope_install$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('authority_metadata_service_account_access_label_ready_v1()','cc3e2aff7e31c47fa51bc7a63e29d98c5b40759b4b1d1f6e86dcec6b85c58472','a1bdb56d1e1124945c6463490415027d3524497d6d077589cb44c4e249df4592',$changes$[
 [
  "d03bfd87fb04ec3da910fb119b13d2061dd248316e799a317cae3bdf53d39629",
  "6887f5816495ae2a898600a48e57ca2d7bcf8c2a94c64daeefda497752365f45"
 ],
 [
  "49713a25044e6fc0aa577f2433e0a30cb34a252cd3015756ccafc0c09c00cbfa",
  "a3b988f9e0ea9b33843c53062788a37f859bd4a9d5d1c7effbd4488d7cf0b3fe"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','d03bfd87fb04ec3da910fb119b13d2061dd248316e799a317cae3bdf53d39629','6887f5816495ae2a898600a48e57ca2d7bcf8c2a94c64daeefda497752365f45',$changes$[
 [
  "49713a25044e6fc0aa577f2433e0a30cb34a252cd3015756ccafc0c09c00cbfa",
  "a3b988f9e0ea9b33843c53062788a37f859bd4a9d5d1c7effbd4488d7cf0b3fe"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','49713a25044e6fc0aa577f2433e0a30cb34a252cd3015756ccafc0c09c00cbfa','a3b988f9e0ea9b33843c53062788a37f859bd4a9d5d1c7effbd4488d7cf0b3fe',$changes$[
 [
  "  ('_authority_role_move_old_project_match_v1(jsonb,integer,integer,jsonb,jsonb,jsonb,jsonb,text,text)','jsonb',9,ARRAY['p_rules','p_rule_index','p_child_index','p_scope','p_target','p_account','p_mirror','p_project_id','p_mirror_account_id']),\n  ('_authority_role_move_project_copy_support_v1(jsonb,jsonb,jsonb,boolean,jsonb,integer)','jsonb',6,ARRAY['p_graph_receipt','p_role','p_moves','p_definition','p_holders','p_rows']),\n  ('_authority_role_move_project_copy_pairs_v1(jsonb,jsonb,integer)','jsonb',3,ARRAY['p_source','p_holders','p_rows']),\n  ('_authority_role_move_project_copy_plan_hold_v1(jsonb,jsonb,jsonb,jsonb,integer,integer)','jsonb',6,ARRAY['p_plan','p_role','p_moves','p_holders','p_rows','p_reads']),\n  ('_authority_role_move_project_copy_plan_require_v1(jsonb,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_plan','p_copies','p_holders','p_rows','p_reads']),\n  ('_authority_role_move_project_reverse_edges_v1(text,jsonb,integer,integer)','jsonb',4,ARRAY['p_scope_id','p_expected','p_rows','p_reads']),\n  ('_authority_role_move_project_moved_owner_plan_v1(jsonb,jsonb,integer)','jsonb',3,ARRAY['p_role','p_moves','p_rows']),\n  ('_authority_role_move_project_container_scopes_v1(jsonb,integer)','jsonb',2,ARRAY['p_holders','p_rows']),\n  ('_authority_role_move_project_bound_accounts_v1(jsonb,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_predicates','p_holders','p_expected','p_rows','p_reads']),\n  ('_authority_role_move_project_direct_census_v1(jsonb,jsonb,jsonb,jsonb,boolean,boolean,integer,integer)','jsonb',8,ARRAY['p_role','p_moves','p_prepared_holders','p_holders','p_definition','p_replay','p_rows','p_reads']),\n  ('_authority_role_move_project_census_matches_v1(jsonb,jsonb,jsonb,jsonb,jsonb,boolean,boolean,jsonb,integer,integer)','jsonb',10,ARRAY['p_role','p_moves','p_project_ids','p_prepared_holders','p_holders','p_definition','p_replay','p_copies','p_rows','p_reads']),\n  ('_authority_role_move_bound_project_census_v1(jsonb,jsonb,jsonb,jsonb,jsonb,integer,integer)','jsonb',7,ARRAY['p_role','p_moves','p_holders','p_copies','p_expected','p_rows','p_reads']),\n  ('_authority_role_move_definition_project_census_v1(jsonb,jsonb,jsonb,jsonb,integer,integer)','jsonb',6,ARRAY['p_role','p_moves','p_copies','p_expected','p_rows','p_reads']),\n  ('_authority_role_move_iam_copy_sources_hold_v2(text,text,jsonb,jsonb,jsonb,text,text,integer,integer)','jsonb',9,ARRAY['p_root_type','p_root_id','p_expected','p_access_labels','p_project_source','p_actor_type','p_actor_id','p_rows','p_reads']),\n",
  "  ('_authority_role_move_old_project_match_v1(jsonb,integer,integer,jsonb,jsonb,jsonb,jsonb,text,text)','jsonb',9,ARRAY['p_rules','p_rule_index','p_child_index','p_scope','p_target','p_account','p_mirror','p_project_id','p_mirror_account_id']),\n"
 ],
 [
  " ('_authority_role_move_old_project_match_v1(jsonb,integer,integer,jsonb,jsonb,jsonb,jsonb,text,text)','7410529c62e5b4fb4e4fe5989ddab8135befa4d16a27b7e8fb38bb981d1969c3',false,'i',true,'private'),\n ('_authority_role_move_project_copy_support_v1(jsonb,jsonb,jsonb,boolean,jsonb,integer)','56e979a2a932e6756fd8b62378e7c31a68f8f802ac414065a797177cb4d92a9b',false,'i',true,'private'),\n ('_authority_role_move_project_copy_pairs_v1(jsonb,jsonb,integer)','9d631da8d3cd6cba9d14d8ccd2f4fd3b68f84c219bcc36e3b192258b58cbdc7c',false,'i',true,'private'),\n ('_authority_role_move_project_copy_plan_hold_v1(jsonb,jsonb,jsonb,jsonb,integer,integer)','c76c3b6bdbe79a656dd49e8da67b68b03b941236fb0e4eb9a23df2bb901bd447',false,'v',true,'private'),\n ('_authority_role_move_project_copy_plan_require_v1(jsonb,jsonb,jsonb,integer,integer)','791eeefcf8dfedd77f65e8bd3ef7bb129fdba21a0f2b8cea20ebd6a123038d3e',false,'v',true,'private'),\n ('_authority_role_move_project_reverse_edges_v1(text,jsonb,integer,integer)','67988d0eaacbc251f3d2baccab29aab3aed94de504ffbc79b3a3e288e872e4cc',false,'v',true,'private'),\n ('_authority_role_move_project_moved_owner_plan_v1(jsonb,jsonb,integer)','55c5b519f26151ade2c3c3bd12b25becce864e32ff3ab16ebe7cff43629b0e67',false,'i',true,'private'),\n ('_authority_role_move_project_container_scopes_v1(jsonb,integer)','12e258d400b23aac7aea899275b595f7e34b090094354e80fdf90333d08a31b6',false,'i',true,'private'),\n ('_authority_role_move_project_bound_accounts_v1(jsonb,jsonb,jsonb,integer,integer)','22b24ae00b4aa760a50760f49afc70583d6cd978bcca4478ed55a6af6037c0f0',false,'v',true,'private'),\n ('_authority_role_move_project_direct_census_v1(jsonb,jsonb,jsonb,jsonb,boolean,boolean,integer,integer)','bcde4a6ec83a5d788726740a3d1139574c9f94f0c60f2c8a1bd2aa54b940add4',false,'v',true,'private'),\n ('_authority_role_move_project_census_matches_v1(jsonb,jsonb,jsonb,jsonb,jsonb,boolean,boolean,jsonb,integer,integer)','c6ea8c541a2f88a211c8cb39c4598e446fb34a3d36b71f64bbf47cd200303b67',false,'v',true,'private'),\n ('_authority_role_move_bound_project_census_v1(jsonb,jsonb,jsonb,jsonb,jsonb,integer,integer)','f42af8290e412013bc61aecea021712a0683a95f0823b47ff9b35c4ac8b6c11d',false,'v',true,'private'),\n ('_authority_role_move_definition_project_census_v1(jsonb,jsonb,jsonb,jsonb,integer,integer)','ce16ca61fb0e4b91914d905e6040cd117a8c79c9c160d6bc86b7f1dac05ddcda',false,'v',true,'private'),\n ('_authority_role_move_iam_copy_sources_hold_v2(text,text,jsonb,jsonb,jsonb,text,text,integer,integer)','2a015c19d649511f7021d30a4626d5eb87f7b40b76e8c980b16eb922eba90e0e',false,'v',true,'private'),\n",
  " ('_authority_role_move_old_project_match_v1(jsonb,integer,integer,jsonb,jsonb,jsonb,jsonb,text,text)','7410529c62e5b4fb4e4fe5989ddab8135befa4d16a27b7e8fb38bb981d1969c3',false,'i',true,'private'),\n"
 ],
 [
  "de4d128e08cb26f3762f97f89953459ba1c7037e16b070c647eb87eb180ea1e2",
  "8818e245bf1517db88a091c9bbb9b950da510eaa50db01f685a6772e49d68e27"
 ],
 [
  "780972ca904bcf3d09f504fa405b4e375f58c2fc7cfc026708df286059ec589c",
  "8fe4c3a1e587d9f09db5bd5e7a73df6795166457f57badf53087e1dd0107dd62"
 ],
 [
  "048d1168e4f57413c03a850a2cfab860a2d76f8ee1d7bb5a3900de43c8930d36",
  "3ad9612a52ef6d3d615c94439e62dfb7a1da6d545cec876867389a718cba4576"
 ],
 [
  "3a04707b697d8afeb8a90b10bd59b5c488e5a7e0c385c47b0e8ee48752720a87",
  "99c34be6e35ca9b1b1b97ea0c16f6c1b4768c3c000d3613136ac9f1f9a5cdbea"
 ]
]$changes$::jsonb),
  ('_authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)','de4d128e08cb26f3762f97f89953459ba1c7037e16b070c647eb87eb180ea1e2','8818e245bf1517db88a091c9bbb9b950da510eaa50db01f685a6772e49d68e27',$changes$[
 [
  "    IF jsonb_path_exists(p_frozen#>'{copies,roots}','$.*.project_source') THEN\n        held_project_cost:=kaname._authority_role_move_project_copy_plan_require_v1(\n            p_frozen#>'{copies,roots}',p_copies,binding_new->'holders',p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(held_project_cost->>'rows')::integer;\n        used_reads:=used_reads+(held_project_cost->>'reads')::integer;\n    END IF;\n    result:=kaname._authority_role_move_copy_requirements_require_v1",
  "    result:=kaname._authority_role_move_copy_requirements_require_v1"
 ],
 [
  "    IF p_frozen ? 'definition_project_copy' THEN\n        IF p_frozen->'binding_census' IS DISTINCT FROM '{\"bindings\":[],\"subjects\":[],\"members\":[],\"ledger\":[]}'::jsonb\n            OR binding_new->'holders' IS DISTINCT FROM '{}'::jsonb THEN\n            RAISE EXCEPTION 'held definition project copy has binding carriers' USING ERRCODE='40001';\n        END IF;\n        definition_projects:=kaname._authority_role_move_definition_project_census_v1(\n            actual_role_row->2,p_frozen#>'{definition_project_copy,moves}',p_copies,\n            p_frozen#>'{definition_project_copy,source}',p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(definition_projects->>'rows')::integer;\n        used_reads:=used_reads+(definition_projects->>'reads')::integer;\n    END IF;\n    IF p_frozen ? 'bound_project_copy' THEN\n        bound_projects:=kaname._authority_role_move_bound_project_census_v1(\n            actual_role_row->2,p_frozen#>'{bound_project_copy,moves}',binding_new->'holders',p_copies,\n            p_frozen#>'{bound_project_copy,source}',p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(bound_projects->>'rows')::integer;\n        used_reads:=used_reads+(bound_projects->>'reads')::integer;\n    END IF;\n    predicates:=kaname._authority_role_move_predicate_plan_v1",
  "    predicates:=kaname._authority_role_move_predicate_plan_v1"
 ],
 [
  "    binding_new jsonb;\n    held_project_cost jsonb;\n    definition_projects jsonb;\n    bound_projects jsonb;",
  "    binding_new jsonb;"
 ]
]$changes$::jsonb),
  ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','780972ca904bcf3d09f504fa405b4e375f58c2fc7cfc026708df286059ec589c','8fe4c3a1e587d9f09db5bd5e7a73df6795166457f57badf53087e1dd0107dd62',$changes$[
 [
  "        IF eligible IS NULL THEN\n            eligible:=kaname._authority_role_move_binding_new_v1(frozen,carriers->'binding_status',p_rows-used_rows);\n            used_rows:=used_rows+(eligible->>'rows')::integer;\n        END IF;\n        bound_projects:=kaname._authority_role_move_bound_project_census_v1(\n            role_image#>'{physical,2}',p_input->'moves',eligible->'holders',prepared_plan,NULL,p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(bound_projects->>'rows')::integer;\n        used_reads:=used_reads+(bound_projects->>'reads')::integer;\n        IF bound_projects->'source'<>'null'::jsonb THEN\n            frozen:=frozen||jsonb_build_object('bound_project_copy',jsonb_build_object(\n                'moves',p_input->'moves','source',bound_projects->'source'));\n        END IF;",
  "        eligible:=kaname._authority_role_move_binding_new_v1(frozen,carriers->'binding_status',p_rows-used_rows);\n        used_rows:=used_rows+(eligible->>'rows')::integer;"
 ],
 [
  "    IF carriers->'old'='{\"bindings\":[],\"subjects\":[],\"members\":[],\"ledger\":[]}'::jsonb\n        AND (coalesce(role_image#>>'{physical,2,account_id}','')<>'' OR coalesce(role_image#>>'{physical,2,project_id}','')<>'') THEN\n        definition_projects:=kaname._authority_role_move_definition_project_census_v1(\n            role_image#>'{physical,2}',p_input->'moves',prepared_plan,NULL,p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(definition_projects->>'rows')::integer;\n        used_reads:=used_reads+(definition_projects->>'reads')::integer;\n        IF definition_projects->'source'<>'null'::jsonb THEN\n            frozen:=frozen||jsonb_build_object('definition_project_copy',jsonb_build_object(\n                'moves',p_input->'moves','source',definition_projects->'source'));\n        END IF;\n    END IF;\n    IF selector_source IS NULL THEN",
  "    IF selector_source IS NULL THEN"
 ],
 [
  "    prepared_plan:=p_input->'copy_candidates';\n    IF jsonb_path_exists(prepared_plan,'$[*].project_source') THEN\n        eligible:=kaname._authority_role_move_binding_new_v1(\n            jsonb_build_object('role_id',p_input->>'role_id','role',role_image,'binding_census',carriers->'old'),\n            carriers->'binding_status',p_rows-used_rows);\n        used_rows:=used_rows+(eligible->>'rows')::integer;\n        project_hold:=kaname._authority_role_move_project_copy_plan_hold_v1(prepared_plan,role_image#>'{physical,2}',\n            p_input->'moves',eligible->'holders',p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(project_hold->>'rows')::integer;\n        used_reads:=used_reads+(project_hold->>'reads')::integer;\n        prepared_plan:=project_hold->'plan';\n    END IF;\n    copies:=kaname._authority_role_move_copy_requirements_hold_v1(prepared_plan,",
  "    copies:=kaname._authority_role_move_copy_requirements_hold_v1(p_input->'copy_candidates',"
 ],
 [
  "    eligible jsonb;\n    prepared_plan jsonb;\n    project_hold jsonb;\n    definition_projects jsonb;\n    bound_projects jsonb;",
  "    eligible jsonb;"
 ]
]$changes$::jsonb),
  ('_authority_role_move_copy_requirements_hold_v1(jsonb,text,text,integer,integer)','048d1168e4f57413c03a850a2cfab860a2d76f8ee1d7bb5a3900de43c8930d36','3ad9612a52ef6d3d615c94439e62dfb7a1da6d545cec876867389a718cba4576',$changes$[
 [
  "        IF root ? 'project_source' THEN\n            held:=kaname._authority_role_move_iam_copy_sources_hold_v2(root_type,root_id,\n                root->'physical',root->'new_access_labels',root->'project_source',p_actor_type,p_actor_id,\n                p_rows-used_rows,p_reads-used_reads);\n        ELSIF root_type IN ('iam.account','iam.project','iam.serviceAccount') THEN",
  "        IF root_type IN ('iam.account','iam.project','iam.serviceAccount') THEN"
 ],
 [
  "root-ARRAY['root_type','root_id','physical','new_access_labels','project_source']",
  "root-ARRAY['root_type','root_id','physical','new_access_labels']"
 ]
]$changes$::jsonb),
  ('_authority_role_move_iam_copy_sources_hold_v1(text,text,jsonb,jsonb,text,text,integer,integer)','3a04707b697d8afeb8a90b10bd59b5c488e5a7e0c385c47b0e8ee48752720a87','99c34be6e35ca9b1b1b97ea0c16f6c1b4768c3c000d3613136ac9f1f9a5cdbea',$changes$[
 [
  "\nBEGIN\n    RETURN kaname._authority_role_move_iam_copy_sources_hold_v2(p_root_type,p_root_id,p_expected,p_access_labels,\n        NULL,p_actor_type,p_actor_id,p_rows,p_reads);\nEND;\n",
  "\nDECLARE\n    table_name text;\n    resource_kind text;\n    physical jsonb;\n    old_row jsonb;\n    old_access jsonb;\n    definitions jsonb;\n    sources jsonb;\n    used_rows integer:=1;\n    used_reads integer:=1;\nBEGIN\n    PERFORM kaname.authority_protocol_require_owner();\n    IF current_setting('transaction_isolation') IS DISTINCT FROM 'read committed' THEN\n        RAISE EXCEPTION 'copy source capture requires READ COMMITTED' USING ERRCODE='25001';\n    END IF;\n    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000\n        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN\n        RAISE EXCEPTION 'copy source capture budget exhausted' USING ERRCODE='54000';\n    END IF;\n    SELECT t.rel,t.kind INTO table_name,resource_kind FROM (VALUES\n        ('iam.account','accounts','account'),\n        ('iam.project','projects','project'),\n        ('iam.serviceAccount','service_accounts','service_account')\n    ) t(dotted,rel,kind) WHERE t.dotted=p_root_type;\n    IF table_name IS NULL OR coalesce(p_root_id,'')=''\n        OR jsonb_typeof(p_expected) IS DISTINCT FROM 'array'\n        OR kaname.access_labels_valid_v1(p_access_labels) IS DISTINCT FROM true THEN\n        RAISE EXCEPTION 'invalid IAM copy root or proposed access labels' USING ERRCODE='42501';\n    END IF;\n\n    EXECUTE format('SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r))\n        FROM ONLY kaname.%I r WHERE r.id=$1 FOR UPDATE OF r NOWAIT',table_name)\n        INTO physical USING p_root_id;\n    IF physical IS NULL OR physical IS DISTINCT FROM p_expected THEN\n        RAISE EXCEPTION 'IAM copy root changed before capture' USING ERRCODE='40001';\n    END IF;\n    old_row:=physical->2;\n    old_access:=old_row->'access_labels';\n    IF kaname.access_labels_valid_v1(old_access) IS DISTINCT FROM true\n        OR jsonb_typeof(old_row->'labels') IS DISTINCT FROM 'object'\n        OR NOT (p_access_labels @> old_access) OR p_access_labels=old_access THEN\n        RAISE EXCEPTION 'IAM selector move must only add protected copies' USING ERRCODE='42501';\n    END IF;\n    used_rows:=used_rows+(SELECT count(*) FROM jsonb_object_keys(p_access_labels));\n    IF used_rows>p_rows THEN\n        RAISE EXCEPTION 'copy source capture budget exhausted' USING ERRCODE='54000';\n    END IF;\n    IF EXISTS (SELECT FROM jsonb_each(p_access_labels) n\n        WHERE NOT (old_access ? n.key) AND n.value IS DISTINCT FROM (old_row->'labels'->n.key)) THEN\n        RAISE EXCEPTION 'protected copy differs from the physical ordinary label' USING ERRCODE='42501';\n    END IF;\n\n    used_rows:=used_rows+2;\n    used_reads:=used_reads+2;\n    IF used_rows>p_rows OR used_reads>p_reads THEN\n        RAISE EXCEPTION 'copy source capture budget exhausted' USING ERRCODE='54000';\n    END IF;\n    PERFORM kaname._authority_role_move_copy_registry_hold_v1();\n    definitions:=kaname._authority_resource_access_label_requirements_v1(resource_kind,\n        old_row,jsonb_set(old_row,'{access_labels}',p_access_labels),p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(definitions->>'rows')::integer;\n    used_reads:=used_reads+(definitions->>'reads')::integer;\n    sources:=kaname._authority_resource_access_label_sources_hold_v1(p_actor_type,p_actor_id,\n        definitions->'requirements',p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(sources->>'rows')::integer;\n    used_reads:=used_reads+(sources->>'reads')::integer;\n    IF used_rows IS NULL OR used_rows>p_rows OR used_reads IS NULL OR used_reads>p_reads THEN\n        RAISE EXCEPTION 'copy source capture budget exhausted' USING ERRCODE='54000';\n    END IF;\n    RETURN jsonb_build_object('root_type',p_root_type,'root_id',p_root_id,'physical',physical,\n        'new_access_labels',p_access_labels,'requirements',definitions->'requirements','authority',sources,\n        'rows',used_rows,'reads',used_reads);\nEND;\n"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move project source custody predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move project source custody splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move project source custody body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move project source custody function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move project source custody function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move project source custody custody differs after migration' USING ERRCODE='55000';END IF;
END;
$scope_install$;
-- +goose StatementEnd
DROP FUNCTION kaname._authority_role_move_iam_copy_sources_hold_v2(text,text,jsonb,jsonb,jsonb,text,text,integer,integer);
DROP FUNCTION kaname._authority_role_move_definition_project_census_v1(jsonb,jsonb,jsonb,jsonb,integer,integer);
DROP FUNCTION kaname._authority_role_move_bound_project_census_v1(jsonb,jsonb,jsonb,jsonb,jsonb,integer,integer);
DROP FUNCTION kaname._authority_role_move_project_census_matches_v1(jsonb,jsonb,jsonb,jsonb,jsonb,boolean,boolean,jsonb,integer,integer);
DROP FUNCTION kaname._authority_role_move_project_direct_census_v1(jsonb,jsonb,jsonb,jsonb,boolean,boolean,integer,integer);
DROP FUNCTION kaname._authority_role_move_project_bound_accounts_v1(jsonb,jsonb,jsonb,integer,integer);
DROP FUNCTION kaname._authority_role_move_project_container_scopes_v1(jsonb,integer);
DROP FUNCTION kaname._authority_role_move_project_moved_owner_plan_v1(jsonb,jsonb,integer);
DROP FUNCTION kaname._authority_role_move_project_reverse_edges_v1(text,jsonb,integer,integer);
DROP FUNCTION kaname._authority_role_move_project_copy_plan_require_v1(jsonb,jsonb,jsonb,integer,integer);
DROP FUNCTION kaname._authority_role_move_project_copy_plan_hold_v1(jsonb,jsonb,jsonb,jsonb,integer,integer);
DROP FUNCTION kaname._authority_role_move_project_copy_pairs_v1(jsonb,jsonb,integer);
DROP FUNCTION kaname._authority_role_move_project_copy_support_v1(jsonb,jsonb,jsonb,boolean,jsonb,integer);
