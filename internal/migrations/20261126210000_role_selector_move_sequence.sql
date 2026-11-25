-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Компилятор прежней роли остаётся общим для обычной записи и переноса.
-- Закрытая ветка добавляет к одному максимуму журнал выбранных IAM-корней.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_root_journal_v1(p_command jsonb,p_ordinal integer)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $journal$
DECLARE
    root_type text:=p_command->>'root_type';
    root_id text:=p_command->>'root_id';
    old_row jsonb:=p_command#>'{physical,2}';
    labels jsonb:=p_command->'access_labels';
    next_row jsonb;
    resource_kind text;
    source_table text;
BEGIN
    IF p_command->>'table'='resource_mirror' AND root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') THEN
        RETURN NULL;
    END IF;
    SELECT t.kind,t.rel INTO resource_kind,source_table FROM (VALUES
        ('iam.account','account','accounts'),('iam.project','project','projects'),
        ('iam.serviceAccount','iam_service_account','service_accounts')) t(typ,kind,rel)
    WHERE t.typ=root_type;
    IF source_table IS NULL OR p_command->>'table' IS DISTINCT FROM source_table
        OR p_ordinal IS NULL OR p_ordinal NOT BETWEEN 1 AND 100000
        OR coalesce(root_id,'')='' OR old_row->>'id' IS DISTINCT FROM root_id
        OR kaname.access_labels_valid_v1(labels) IS DISTINCT FROM true
        OR (labels @> (old_row->'access_labels')) IS DISTINCT FROM true OR labels=old_row->'access_labels' THEN
        RAISE EXCEPTION 'invalid selector move journal command' USING ERRCODE='42501';
    END IF;
    next_row:=jsonb_set(old_row,'{access_labels}',labels,false);
    RETURN jsonb_build_object('table','resource_journal','ordinal',p_ordinal,'stamp','transaction',
        'origin',jsonb_build_object('table',source_table,'operation','UPDATE','when','AFTER','old',old_row,'new',next_row),
        'row',jsonb_build_object('resource_kind',resource_kind,'resource_id',root_id,
            'project_id',kaname.resource_journal_project(resource_kind,next_row),
            'scope',kaname.resource_journal_scope(resource_kind,next_row),'event_type','UPDATED',
            'payload',jsonb_build_object('id',root_id)));
END;
$journal$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_sequence_extend_v1(
    p_frozen jsonb,p_fixed integer,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $extend$
DECLARE
    slots jsonb[]:=ARRAY[]::jsonb[];
    outputs jsonb:='{}'::jsonb;
    root record;
    source_table text;
    command jsonb;
    slot jsonb;
    cluster_count integer:=0;
    cluster_bytes bigint:=0;
    used_rows integer:=2;
    used_reads integer:=2;
    used_bytes bigint:=2;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN
        RAISE EXCEPTION 'selector move reservation budget exhausted' USING ERRCODE='54000';
    END IF;
    IF p_frozen#>'{copies,roots}'<>'{}'::jsonb THEN
        -- Закрытый producer следующей миграции резервирует аудит, reconcile и поколения.
        outputs:=kaname._authority_role_move_root_outputs_hold_v1(p_frozen,p_rows-used_rows,p_reads-used_reads);
        IF jsonb_typeof(outputs->'roots') IS DISTINCT FROM 'object'
            OR (outputs->>'rows')::integer IS NULL OR (outputs->>'rows')::integer NOT BETWEEN 0 AND p_rows-used_rows
            OR (outputs->>'reads')::integer IS NULL OR (outputs->>'reads')::integer NOT BETWEEN 0 AND p_reads-used_reads THEN
            RAISE EXCEPTION 'selector move root reservation incomplete' USING ERRCODE='42501';
        END IF;
        used_rows:=used_rows+(outputs->>'rows')::integer;
        used_reads:=used_reads+(outputs->>'reads')::integer;
        outputs:=outputs->'roots';
        IF EXISTS(SELECT key FROM jsonb_each(p_frozen#>'{copies,roots}') EXCEPT SELECT key FROM jsonb_each(outputs))
            OR EXISTS(SELECT key FROM jsonb_each(outputs) EXCEPT SELECT key FROM jsonb_each(p_frozen#>'{copies,roots}')) THEN
            RAISE EXCEPTION 'selector move root reservation set differs' USING ERRCODE='42501';
        END IF;
    END IF;
    IF EXISTS(SELECT FROM jsonb_each(p_frozen#>'{copies,roots}') r WHERE r.value->>'root_type'='iam.account') THEN
        -- resource_journal_scope(account) использует все clusters. Считаем и
        -- удерживаем полный набор до clock, включая отсутствие новых кластеров.
        LOCK TABLE ONLY kaname.clusters IN SHARE MODE NOWAIT;
        IF EXISTS(SELECT FROM pg_inherits WHERE inhparent='kaname.clusters'::regclass)
            OR NOT EXISTS(SELECT FROM pg_class WHERE oid='kaname.clusters'::regclass AND relkind='r'
                AND NOT relispartition AND NOT relrowsecurity AND NOT relforcerowsecurity) THEN
            RAISE EXCEPTION 'selector move account journal scope is not closed' USING ERRCODE='42501';
        END IF;
        SELECT count(*)::integer,coalesce(sum(octet_length(to_json(id)::text)+40),0)
        INTO cluster_count,cluster_bytes FROM (SELECT id FROM ONLY kaname.clusters LIMIT p_rows-used_rows+1) c;
        used_rows:=used_rows+cluster_count;used_reads:=used_reads+3;
    END IF;
    FOR root IN SELECT key,value FROM jsonb_each(p_frozen#>'{copies,roots}') ORDER BY key COLLATE "C" LOOP
        used_rows:=used_rows+1;
        IF used_rows>p_rows OR used_reads>p_reads THEN
            RAISE EXCEPTION 'selector move journal reservation exhausted' USING ERRCODE='54000';
        END IF;
        source_table:=CASE root.value->>'root_type' WHEN 'iam.account' THEN 'accounts'
            WHEN 'iam.project' THEN 'projects' WHEN 'iam.serviceAccount' THEN 'service_accounts' END;
        IF source_table IS NULL THEN CONTINUE;END IF;
        used_rows:=used_rows+1;
        IF source_table='accounts' THEN
            used_rows:=used_rows+cluster_count;used_reads:=used_reads+1;
            IF used_bytes+cluster_bytes>8388608 THEN
                RAISE EXCEPTION 'selector move account scope exceeds byte budget' USING ERRCODE='54000';
            END IF;
        END IF;
        IF used_rows>p_rows OR used_reads>p_reads OR p_fixed+cardinality(slots)>=100000 THEN
            RAISE EXCEPTION 'selector move journal reservation exhausted' USING ERRCODE='54000';
        END IF;
        command:=jsonb_build_object('root_type',root.value->'root_type','root_id',root.value->'root_id',
            'physical',root.value->'physical','access_labels',root.value->'new_access_labels','table',source_table);
        slot:=kaname._authority_role_move_root_journal_v1(command,p_fixed+cardinality(slots)+1);
        used_bytes:=used_bytes+octet_length(slot::text)+2;
        IF used_bytes>8388608 THEN
            RAISE EXCEPTION 'selector move journal slots exceed byte budget' USING ERRCODE='54000';
        END IF;
        slots:=array_append(slots,slot);
    END LOOP;
    RETURN jsonb_build_object('slots',to_jsonb(slots),'outputs',outputs,'rows',used_rows,'reads',used_reads);
END;
$extend$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_sequence_publish_v1(
    p_copies jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $publish$
DECLARE
    p_program jsonb:=kaname._authority_sequence_store_v3();
    frozen jsonb:=p_program->'frozen';
    fixed integer:=(frozen->>'selector_move_fixed')::integer;
    decision jsonb;
    chosen jsonb;
    discarded jsonb;
    matched integer;
    at_time timestamptz;
    slot_count integer:=jsonb_array_length(p_program->'maximum');
    row_cost integer;
BEGIN
    IF p_program->>'family' IS DISTINCT FROM 'role' OR frozen->>'kind' IS DISTINCT FROM 'role.mutation'
        OR fixed IS NULL OR fixed NOT BETWEEN 1 AND slot_count
        OR jsonb_typeof(p_copies) IS DISTINCT FROM 'array' OR p_program->'selected' IS DISTINCT FROM 'null'::jsonb
        OR frozen ? 'selector_move_decision' OR frozen ? 'selector_move_approved' THEN
        RAISE EXCEPTION 'selector move has no open mixed reservation' USING ERRCODE='42501';
    END IF;
    row_cost:=slot_count+jsonb_array_length(p_copies)+4;
    IF p_rows IS NULL OR p_rows NOT BETWEEN row_cost AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 4 AND 4096 THEN
        RAISE EXCEPTION 'selector move publication budget exhausted' USING ERRCODE='54000';
    END IF;
    decision:=kaname._authority_role_move_require_checks_v1(frozen->'selector_move',p_copies,p_rows-row_cost,p_reads-4);
    at_time:=(decision->>'decision_at')::timestamptz;
    -- Для fixed descriptors остаётся старый предикат TTL. IAM slots существуют
    -- лишь для held OLD. NEW может потерять ключи после TTL. Journal row зависит
    -- от неизменных координат, а scope уже удержан до обновления часов.
    WITH commands AS MATERIALIZED (
        SELECT c.value AS cmd FROM jsonb_array_elements(decision->'commands') c WHERE c.value->>'table'<>'resource_mirror'
    ), entries AS MATERIALIZED (
        SELECT s.value AS slot,s.position,c.cmd,
            CASE WHEN s.position<=fixed THEN
                frozen#>>ARRAY['expiry',s.value->>'ordinal'] IS NULL
                OR (frozen#>>ARRAY['expiry',s.value->>'ordinal'])::timestamptz>at_time
            ELSE c.cmd IS NOT NULL END AS selected
        FROM jsonb_array_elements(p_program->'maximum') WITH ORDINALITY s(value,position)
        LEFT JOIN commands c ON s.position>fixed AND c.cmd->>'table'=s.value#>>'{origin,table}'
            AND c.cmd->>'root_id'=s.value#>>'{origin,old,id}'
            AND c.cmd#>'{physical,2}'=s.value#>'{origin,old}'
            AND (s.value#>'{origin,new,access_labels}') @> (c.cmd->'access_labels')
    )
    SELECT coalesce(jsonb_agg((CASE WHEN cmd IS NULL THEN slot ELSE
            jsonb_set(slot,'{origin,new,access_labels}',cmd->'access_labels',false) END)
            ||jsonb_build_object('row',(slot->'row')||jsonb_build_object('created_at',
                CASE slot->>'stamp' WHEN 'transaction' THEN transaction_timestamp() ELSE at_time END))
            ORDER BY position) FILTER (WHERE selected),'[]'::jsonb),
        coalesce(jsonb_agg(slot->'ordinal' ORDER BY position) FILTER (WHERE NOT selected),'[]'::jsonb),
        count(cmd)::integer INTO chosen,discarded,matched FROM entries;
    IF matched<>(SELECT count(*) FROM jsonb_array_elements(decision->'commands') c WHERE c->>'table'<>'resource_mirror')
        OR jsonb_array_length(chosen)+jsonb_array_length(discarded)<>slot_count THEN
        RAISE EXCEPTION 'selector move commands differ from reserved journal slots' USING ERRCODE='42501';
    END IF;
    -- До одобрения результат хранится в программе, а слоты недоступны триггерам.
    UPDATE pg_temp.kaname_authority_sequence_program s SET frozen=s.frozen||jsonb_build_object(
        'selector_move_decision',decision,
        'selector_move_pending',jsonb_build_object('selected',chosen,'unselected',discarded))
    WHERE s.singleton AND s.nonce=(p_program->>'nonce')::uuid AND s.family='role' AND s.selected IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION 'selector move selection changed' USING ERRCODE='42501';END IF;
    RETURN jsonb_build_object('rows',row_cost+(decision->>'rows')::integer,'reads',4+(decision->>'reads')::integer);
END;
$publish$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_sequence_approve_v1()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $approve$
DECLARE proof jsonb;program jsonb;decision jsonb;pending jsonb;approval jsonb;
BEGIN
    proof:=kaname._authority_role_move_attestation_v1();
    program:=kaname._authority_sequence_store_v3();
    decision:=program#>'{frozen,selector_move_decision}';
    pending:=program#>'{frozen,selector_move_pending}';
    IF program->>'family' IS DISTINCT FROM 'role' OR program#>>'{frozen,kind}' IS DISTINCT FROM 'role.mutation'
        OR program->'selected' IS DISTINCT FROM 'null'::jsonb
        OR jsonb_typeof(pending->'selected') IS DISTINCT FROM 'array'
        OR jsonb_typeof(pending->'unselected') IS DISTINCT FROM 'array'
        OR jsonb_typeof(decision->'commands') IS DISTINCT FROM 'array'
        OR decision->'role_id' IS DISTINCT FROM program#>'{frozen,selector_move,role_id}'
        OR decision->'actor' IS DISTINCT FROM program#>'{frozen,selector_move,actor}'
        OR (decision->>'decision_at')::timestamptz IS DISTINCT FROM (proof->>'decision_at')::timestamptz
        OR (program->'frozen') ? 'selector_move_approved' THEN
        RAISE EXCEPTION 'selector move approval outside final untouched program' USING ERRCODE='42501';
    END IF;
    approval:=jsonb_build_object('nonce',proof->'nonce','decision_at',proof->'decision_at',
        'role_id',decision->'role_id','actor',decision->'actor');
    -- Штатный publisher дополнительно сверяет nonce, резерв и отсутствие использованных слотов.
    PERFORM kaname._authority_sequence_publish_v3(pending->'selected');
    UPDATE pg_temp.kaname_authority_sequence_program s
    SET selected=pending->'selected',unselected=pending->'unselected',
        selected_count=jsonb_array_length(pending->'selected'),decision_at=(proof->>'decision_at')::timestamptz,
        frozen=(s.frozen-'selector_move_pending')||jsonb_build_object('selector_move_approved',approval)
    WHERE s.singleton AND s.nonce=(proof->>'nonce')::uuid AND s.selected IS NULL
        AND NOT (s.frozen ? 'selector_move_approved');
    IF NOT FOUND THEN RAISE EXCEPTION 'selector move approval repeated' USING ERRCODE='42501';END IF;
END;
$approve$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $compile$
DECLARE item record; fn regprocedure; old_body text; definition text; body text; pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','_authority_role_move_sequence_prepare_v1(jsonb,jsonb,jsonb,integer,integer)','_authority_role_move_sequence_prepare_v1(p_input jsonb,p_move jsonb,p_actor jsonb,p_rows integer,p_reads integer)','0890abdfa2517000901077218dde1cbe48b465003ce4c8e5e74559a2ebaa167e','157d289b31d5bb2e1901df54ef5b60e9c08ace47518da56e0ffdff80c4c4a9fc','a2f5785344e6e53ce74cc1eafb3fcc8e234956b90837e010d70803d9f146061e',$wrapper$
BEGIN
 RETURN kaname._authority_role_move_sequence_prepare_v1(p_input,NULL,NULL,p_rows,p_reads);
END $wrapper$,$pairs$[
 [
  " access_label_authority_input jsonb;access_label_authority jsonb;",
  " access_label_authority_input jsonb;access_label_authority jsonb;\n move_checks jsonb;move_frozen jsonb;move_extension jsonb;"
 ],
 [
  " cost:=kaname._authority_sequence_reserve_v3('role',maximum,p_reads-reads);",
  " IF p_move IS NOT NULL OR p_actor IS NOT NULL THEN\n  IF p_move IS NULL OR p_actor IS NULL OR creation OR NOT promote\n   OR p_input->'mask' IS DISTINCT FROM '[\"rules\"]'::jsonb\n   OR p_input->>'version' IS DISTINCT FROM p_move->>'version'\n   OR p_input#>>'{role,id}' IS DISTINCT FROM p_move->>'role_id'\n   OR access_label_authority_input->'actor' IS DISTINCT FROM p_actor THEN\n   RAISE EXCEPTION 'selector move differs from role rules request or actor' USING ERRCODE='42501';END IF;\n  move_checks:=kaname._authority_role_move_prepare_checks_v1(p_move,p_actor,p_rows-scanned,p_reads-reads);\n  move_frozen:=move_checks->'frozen';\n  IF move_frozen#>'{role,physical,2}' IS DISTINCT FROM old_role\n   OR move_frozen#>'{role,new_role}' IS DISTINCT FROM jsonb_set(new_role,'{updated_at}',old_role->'updated_at',false)\n   OR maximum#>'{0,origin,new}' IS DISTINCT FROM new_role THEN\n   RAISE EXCEPTION 'selector move differs from exact role journal image' USING ERRCODE='42501';END IF;\n  scanned:=scanned+(move_checks->>'rows')::integer;reads:=reads+(move_checks->>'reads')::integer;\n  move_extension:=kaname._authority_role_move_sequence_extend_v1(move_frozen,jsonb_array_length(maximum),p_rows-scanned,p_reads-reads);\n  scanned:=scanned+(move_extension->>'rows')::integer;reads:=reads+(move_extension->>'reads')::integer;\n  access_label_frozen:=jsonb_build_object('mode','selector_move')||access_label_frozen||jsonb_build_object(\n   'selector_move',move_frozen,'selector_move_fixed',jsonb_array_length(maximum),'selector_move_outputs',move_extension->'outputs');\n  maximum:=maximum||(move_extension->'slots');\n END IF;\n cost:=kaname._authority_sequence_reserve_v3('role',maximum,p_reads-reads);"
 ]
]$pairs$::jsonb),
  ('authority_role_sequence_finalize_v3()','_authority_role_move_sequence_finalize_v1(jsonb,integer,integer)','_authority_role_move_sequence_finalize_v1(p_copies jsonb,p_rows integer,p_reads integer)','0adfc241154b42e561425452f8ceef42eeefa3e802a21111e9e74d5a434830cd','6f0700709a8b82c29973349ae74232b9d1ae57bfb5bf2002fa26432f05efbedf','f500d728c4214be2015a5d7f6ed07c5dc98172fcc0249a98ae56c65a57c51f67',$wrapper$
BEGIN
 PERFORM kaname._authority_role_move_sequence_finalize_v1(NULL,NULL,NULL);
END $wrapper$,$pairs$[
 [
  " required_questions jsonb;",
  " move_cost jsonb;required_questions jsonb;"
 ],
 [
  " SELECT coalesce(array_agg((value->>'ordinal')::integer ORDER BY (value->>'ordinal')::integer),ARRAY[]::integer[]) INTO ordinals\n FROM jsonb_array_elements(program->'maximum')\n WHERE program#>>ARRAY['frozen','expiry',value->>'ordinal'] IS NULL\n  OR (program#>>ARRAY['frozen','expiry',value->>'ordinal'])::timestamptz>at_time;\n PERFORM kaname._authority_sequence_select_v3(ordinals,at_time);\n",
  " IF (program->'frozen') ? 'selector_move' THEN\n  IF p_copies IS NULL THEN\n   RAISE EXCEPTION 'selector move requires its private decision' USING ERRCODE='42501';END IF;\n  move_cost:=kaname._authority_role_move_sequence_publish_v1(p_copies,p_rows,p_reads);\n ELSE\n  IF p_copies IS NOT NULL THEN\n   RAISE EXCEPTION 'selector move requires its own frozen program' USING ERRCODE='42501';END IF;\n SELECT coalesce(array_agg((value->>'ordinal')::integer ORDER BY (value->>'ordinal')::integer),ARRAY[]::integer[]) INTO ordinals\n FROM jsonb_array_elements(program->'maximum')\n WHERE program#>>ARRAY['frozen','expiry',value->>'ordinal'] IS NULL\n  OR (program#>>ARRAY['frozen','expiry',value->>'ordinal'])::timestamptz>at_time;\n PERFORM kaname._authority_sequence_select_v3(ordinals,at_time);\n END IF;\n"
 ],
 [
  "\nEND",
  "\n RETURN move_cost;\nEND"
 ]
]$pairs$::jsonb)
 ) AS x(public_signature,private_signature,private_parameters,original_hash,private_hash,wrapper_hash,wrapper,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.public_signature);
  SELECT prosrc,pg_get_functiondef(oid) INTO STRICT old_body,definition FROM pg_proc
   WHERE oid=fn AND proowner=current_user::regrole AND prosecdef;
  IF length(definition)-length(replace(definition,old_body,''))<>length(old_body)
   OR encode(sha256(convert_to(old_body,'UTF8')),'hex') IS DISTINCT FROM item.original_hash THEN
   RAISE EXCEPTION 'changed role sequence compiler %',item.public_signature USING ERRCODE='55000';END IF;
  body:=old_body;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF length(body)-length(replace(body,pair->>0,''))<>length(pair->>0) THEN
    RAISE EXCEPTION 'role compiler fragment is not unique' USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.private_hash
   OR encode(sha256(convert_to(item.wrapper,'UTF8')),'hex') IS DISTINCT FROM item.wrapper_hash THEN
   RAISE EXCEPTION 'changed compiled role sequence image' USING ERRCODE='55000';END IF;
  EXECUTE format('CREATE FUNCTION kaname.%s RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS %L',item.private_parameters,body);
  EXECUTE replace(definition,old_body,item.wrapper);
 END LOOP;
END;
$compile$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure; grantee record;
BEGIN
 FOREACH fn IN ARRAY ARRAY[
  'kaname._authority_role_move_root_journal_v1(jsonb,integer)'::regprocedure,
  'kaname._authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer)'::regprocedure,
  'kaname._authority_role_move_sequence_publish_v1(jsonb,integer,integer)'::regprocedure,
  'kaname._authority_role_move_sequence_approve_v1()'::regprocedure,
  'kaname._authority_role_move_sequence_prepare_v1(jsonb,jsonb,jsonb,integer,integer)'::regprocedure,
  'kaname._authority_role_move_sequence_finalize_v1(jsonb,integer,integer)'::regprocedure
 ] LOOP
  FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_proc p
   CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   LEFT JOIN pg_roles r ON r.oid=a.grantee WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
    CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
  END LOOP;
 END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $repin$
DECLARE item record; fn regprocedure; prior_body text; body text; definition text; source_literal text; pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('_authority_sequence_complete_v3()','ea51295fc9a86b810572e9400319ae8defec75a270ef20b5ed1ce68acd5a9915','319c4cda0e3e509c803b5429e1184baaf105a1fbdf02b08d833646a193ae02f4',$pairs$[
 [
  " IF program->>'family'='metadata' AND program#>>'{frozen,mode}' IN ('external_ordinary','external_noop') THEN",
  " IF program->>'family'='role' AND program#>>'{frozen,mode}' IN ('selector_move','access_label_transition') THEN\n  IF EXISTS(SELECT FROM pg_temp.kaname_authority_sequence_program s WHERE s.singleton AND s.frozen ? 'selector_move'\n   AND (jsonb_typeof(s.frozen->'selector_move_approved') IS DISTINCT FROM 'object'\n    OR jsonb_typeof(s.frozen#>'{selector_move_decision,commands}') IS DISTINCT FROM 'array'\n    OR (s.frozen#>'{selector_move_decision,commands}'<>'[]'::jsonb AND s.frozen->'selector_move_roots_completed'\n      IS DISTINCT FROM to_jsonb(jsonb_array_length(s.frozen#>'{selector_move_decision,commands}')))) ) THEN\n   RAISE EXCEPTION 'selector move approval or root completion is absent' USING ERRCODE='42501';END IF;\n END IF;\n IF program->>'family'='metadata' AND program#>>'{frozen,mode}' IN ('external_ordinary','external_noop') THEN"
 ]
]$pairs$::jsonb),
  ('authority_role_sequence_stamp_v3(jsonb)','1a76eb48aa2c75c7213b7e01fe7530bfe859348a0fb8cf3cb0d79be83e9dd1f8','8ea1d2e5e9216e08e479cccb484722d3e78e121cdeda01c030062a99cdee4338',$pairs$[
 [
  " RETURN (program#>>'{frozen,stamp}')::timestamptz;",
  " IF (program->'frozen') ? 'selector_move' AND (\n  jsonb_typeof(program#>'{frozen,selector_move_approved}') IS DISTINCT FROM 'object'\n  OR program#>'{frozen,selector_move_approved,nonce}' IS DISTINCT FROM program->'nonce'\n  OR program#>'{frozen,selector_move_approved,actor}' IS DISTINCT FROM program#>'{frozen,selector_move,actor}'\n  OR program#>'{frozen,selector_move_approved,role_id}' IS DISTINCT FROM program#>'{frozen,id}'\n  OR (program#>>'{frozen,selector_move_approved,decision_at}')::timestamptz IS DISTINCT FROM (program->>'decision_at')::timestamptz) THEN\n  RAISE EXCEPTION 'selector move role stamp requires approval' USING ERRCODE='42501';END IF;\n RETURN (program#>>'{frozen,stamp}')::timestamptz;"
 ]
]$pairs$::jsonb),
  ('_authority_crud_storage_v3()','0217a266427178ae68d624340325b5bbd2e8d9d939377db1bebb5396b6af5093','3b2369bd73c9e96a3a2a7825ec68f7ea11b14eaa6a13797c49ef2cf1f3904410',$pairs$[
 [
  "0890abdfa2517000901077218dde1cbe48b465003ce4c8e5e74559a2ebaa167e",
  "a2f5785344e6e53ce74cc1eafb3fcc8e234956b90837e010d70803d9f146061e"
 ],
 [
  "0adfc241154b42e561425452f8ceef42eeefa3e802a21111e9e74d5a434830cd",
  "f500d728c4214be2015a5d7f6ed07c5dc98172fcc0249a98ae56c65a57c51f67"
 ],
 [
  "1a76eb48aa2c75c7213b7e01fe7530bfe859348a0fb8cf3cb0d79be83e9dd1f8",
  "8ea1d2e5e9216e08e479cccb484722d3e78e121cdeda01c030062a99cdee4338"
 ],
 [
  "ea51295fc9a86b810572e9400319ae8defec75a270ef20b5ed1ce68acd5a9915",
  "319c4cda0e3e509c803b5429e1184baaf105a1fbdf02b08d833646a193ae02f4"
 ],
 [
  " ('_authority_role_actor_revoke_grants_v1(oid)','9be92689be1bda5db54c954b756f88eccef63d5fdb73de2a9d121c0629b15e86',false,'v',true,'private'),",
  " ('_authority_role_actor_revoke_grants_v1(oid)','9be92689be1bda5db54c954b756f88eccef63d5fdb73de2a9d121c0629b15e86',false,'v',true,'private'),\n ('_authority_role_move_copy_registry_hold_v1()','926d2d998342fd05106c52603aa78142f6a8ce73f4d3c7699fa6d4981db1967e',false,'v',true,'private'),\n ('_authority_role_move_iam_copy_sources_hold_v1(text,text,jsonb,jsonb,text,text,integer,integer)','99c34be6e35ca9b1b1b97ea0c16f6c1b4768c3c000d3613136ac9f1f9a5cdbea',false,'v',true,'private'),\n ('_authority_role_move_external_copy_sources_hold_v1(text,text,jsonb,jsonb,text,text,integer,integer)','46e5c2961173bfc399aed60bf270aab42d5c74215e7dc18d4be429356c1bca8e',false,'v',true,'private'),\n ('_authority_role_move_copy_requirements_hold_v1(jsonb,text,text,integer,integer)','3ad9612a52ef6d3d615c94439e62dfb7a1da6d545cec876867389a718cba4576',false,'v',true,'private'),\n ('_authority_role_move_copy_requirements_require_v1(jsonb,jsonb,text,text,timestamptz,integer,integer)','c92e9a006c88a0e30be5ba01b6a2396762de4e2033c685845746e7e309906829',false,'v',true,'private'),\n ('_authority_role_move_role_image_hold_v1(text,text,jsonb,jsonb,jsonb,integer,integer)','c1c04a83e4a4ce0b5f09a13d1aedf91874e7734ab1aef1a414a603e194c394eb',false,'v',true,'private'),\n ('_authority_role_move_attestation_v1()','2db733815c857aad263cfcd93407e86f4594d28b808d569ca075e540005901af',false,'v',true,'private'),\n ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','b62b3fed95dfd39408adf6086649d034fa1fdc39bcc6c7c406ea94e278e34804',false,'v',true,'private'),\n ('_authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)','9644399436d2dca53ab8f629522a88abe0aa16f06eb856b616abd79e73a38927',false,'v',true,'private'),\n ('_authority_role_move_root_journal_v1(jsonb,integer)','19eade41e3bd6c1673dc5a739143c335d67957af1c9a8b66ba2e847708506746',false,'s',true,'private'),\n ('_authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer)','a61a057c02720031cd029075490eb56a6cacabbca9bc18ef1e7d27463a40c577',false,'v',true,'private'),\n ('_authority_role_move_sequence_publish_v1(jsonb,integer,integer)','09b3bbd42c75e5a01bec9fd1b0829b9604e32a3de35ec777ce411e3bb50ff213',false,'v',true,'private'),\n ('_authority_role_move_sequence_approve_v1()','68bf1bae5828e05864b7d6b27986abb0a2123d573f534ddc8e938f7045bdcb7c',false,'v',true,'private'),\n ('_authority_role_move_sequence_prepare_v1(jsonb,jsonb,jsonb,integer,integer)','157d289b31d5bb2e1901df54ef5b60e9c08ace47518da56e0ffdff80c4c4a9fc',false,'v',true,'private'),\n ('_authority_role_move_sequence_finalize_v1(jsonb,integer,integer)','6f0700709a8b82c29973349ae74232b9d1ae57bfb5bf2002fa26432f05efbedf',false,'v',true,'private'),"
 ],
 [
  "  ('_authority_resource_selector_matches_v3(jsonb,text,text,jsonb,jsonb)','boolean',5,ARRAY['p_selector','p_type','p_id','p_labels','p_access_labels']),",
  "  ('_authority_resource_selector_matches_v3(jsonb,text,text,jsonb,jsonb)','boolean',5,ARRAY['p_selector','p_type','p_id','p_labels','p_access_labels']),\n  ('_authority_role_move_copy_registry_hold_v1()','void',0,NULL::text[]),\n  ('_authority_role_move_iam_copy_sources_hold_v1(text,text,jsonb,jsonb,text,text,integer,integer)','jsonb',8,ARRAY['p_root_type','p_root_id','p_expected','p_access_labels','p_actor_type','p_actor_id','p_rows','p_reads']),\n  ('_authority_role_move_external_copy_sources_hold_v1(text,text,jsonb,jsonb,text,text,integer,integer)','jsonb',8,ARRAY['p_root_type','p_root_id','p_expected','p_access_labels','p_actor_type','p_actor_id','p_rows','p_reads']),\n  ('_authority_role_move_copy_requirements_hold_v1(jsonb,text,text,integer,integer)','jsonb',5,ARRAY['p_plan','p_actor_type','p_actor_id','p_rows','p_reads']),\n  ('_authority_role_move_copy_requirements_require_v1(jsonb,jsonb,text,text,timestamptz,integer,integer)','jsonb',7,ARRAY['p_held','p_copies','p_actor_type','p_actor_id','p_at','p_rows','p_reads']),\n  ('_authority_role_move_role_image_hold_v1(text,text,jsonb,jsonb,jsonb,integer,integer)','jsonb',7,ARRAY['p_role_id','p_version','p_expected','p_moves','p_proposed_rules','p_rows','p_reads']),\n  ('_authority_role_move_attestation_v1()','jsonb',0,NULL::text[]),\n  ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_input','p_actor','p_rows','p_reads']),\n  ('_authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_frozen','p_copies','p_rows','p_reads']),\n  ('_authority_role_move_root_journal_v1(jsonb,integer)','jsonb',2,ARRAY['p_command','p_ordinal']),\n  ('_authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer)','jsonb',4,ARRAY['p_frozen','p_fixed','p_rows','p_reads']),\n  ('_authority_role_move_sequence_publish_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_copies','p_rows','p_reads']),\n  ('_authority_role_move_sequence_approve_v1()','void',0,NULL::text[]),\n  ('_authority_role_move_sequence_prepare_v1(jsonb,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_input','p_move','p_actor','p_rows','p_reads']),\n  ('_authority_role_move_sequence_finalize_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_copies','p_rows','p_reads']),"
 ]
]$pairs$::jsonb),
  ('_authority_full_contract_storage_v3()','250c74cf3b696e3337a4845f38d748384e524448cd86872fcaf59f2a6961c841','69b30e1a511507c6d0e27a5e3b0eeb71d2302504e0bd884c01646e134c20d59f',$pairs$[
 [
  "0217a266427178ae68d624340325b5bbd2e8d9d939377db1bebb5396b6af5093",
  "3b2369bd73c9e96a3a2a7825ec68f7ea11b14eaa6a13797c49ef2cf1f3904410"
 ]
]$pairs$::jsonb),
  ('authority_metadata_service_account_access_label_ready_v1()','042ab86ea4d7d0f9deaf4989efa5a51efd43bb8fac1cdcf4ad135ab35d9e5ad7','ddd528b7365fd23685693207053e82a4fba204d2eb55d61f87506889a78c5559',$pairs$[
 [
  "0217a266427178ae68d624340325b5bbd2e8d9d939377db1bebb5396b6af5093",
  "3b2369bd73c9e96a3a2a7825ec68f7ea11b14eaa6a13797c49ef2cf1f3904410"
 ],
 [
  "250c74cf3b696e3337a4845f38d748384e524448cd86872fcaf59f2a6961c841",
  "69b30e1a511507c6d0e27a5e3b0eeb71d2302504e0bd884c01646e134c20d59f"
 ]
]$pairs$::jsonb)
 ) AS pins(signature,before_hash,after_hash,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT prior_body,definition FROM pg_catalog.pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(prior_body,'UTF8')),'hex') IS DISTINCT FROM item.before_hash THEN
   RAISE EXCEPTION 'Исходное тело функции % изменилось',item.signature USING ERRCODE='55000';
  END IF;
  body:=prior_body;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF length(body)-length(replace(body,pair->>0,''))<>length(pair->>0) THEN
    RAISE EXCEPTION 'Фрагмент тела функции % не уникален',item.signature USING ERRCODE='55000';
   END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.after_hash
   OR length(definition)-length(replace(definition,prior_body,''))<>length(prior_body) THEN
   RAISE EXCEPTION 'Расчётный образ функции % изменился',item.signature USING ERRCODE='55000';
  END IF;
  source_literal:=substring(left(definition,strpos(definition,prior_body)-1)
   FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||prior_body||source_literal)=0 THEN
   RAISE EXCEPTION 'Не найден литерал тела функции %',item.signature USING ERRCODE='55000';
  END IF;
  EXECUTE replace(definition,source_literal||prior_body||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
     IS DISTINCT FROM item.after_hash THEN
   RAISE EXCEPTION 'Установленное тело функции % изменилось',item.signature USING ERRCODE='55000';
  END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'Нарушена целостность контракта записи' USING ERRCODE='55000';
 END IF;
END;
$repin$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $compile$
DECLARE item record; fn regprocedure; old_body text; definition text; body text; pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','_authority_role_move_sequence_prepare_v1(jsonb,jsonb,jsonb,integer,integer)','_authority_role_move_sequence_prepare_v1(p_input jsonb,p_move jsonb,p_actor jsonb,p_rows integer,p_reads integer)','0890abdfa2517000901077218dde1cbe48b465003ce4c8e5e74559a2ebaa167e','157d289b31d5bb2e1901df54ef5b60e9c08ace47518da56e0ffdff80c4c4a9fc','a2f5785344e6e53ce74cc1eafb3fcc8e234956b90837e010d70803d9f146061e',$wrapper$
BEGIN
 RETURN kaname._authority_role_move_sequence_prepare_v1(p_input,NULL,NULL,p_rows,p_reads);
END $wrapper$,$pairs$[
 [
  " IF p_move IS NOT NULL OR p_actor IS NOT NULL THEN\n  IF p_move IS NULL OR p_actor IS NULL OR creation OR NOT promote\n   OR p_input->'mask' IS DISTINCT FROM '[\"rules\"]'::jsonb\n   OR p_input->>'version' IS DISTINCT FROM p_move->>'version'\n   OR p_input#>>'{role,id}' IS DISTINCT FROM p_move->>'role_id'\n   OR access_label_authority_input->'actor' IS DISTINCT FROM p_actor THEN\n   RAISE EXCEPTION 'selector move differs from role rules request or actor' USING ERRCODE='42501';END IF;\n  move_checks:=kaname._authority_role_move_prepare_checks_v1(p_move,p_actor,p_rows-scanned,p_reads-reads);\n  move_frozen:=move_checks->'frozen';\n  IF move_frozen#>'{role,physical,2}' IS DISTINCT FROM old_role\n   OR move_frozen#>'{role,new_role}' IS DISTINCT FROM jsonb_set(new_role,'{updated_at}',old_role->'updated_at',false)\n   OR maximum#>'{0,origin,new}' IS DISTINCT FROM new_role THEN\n   RAISE EXCEPTION 'selector move differs from exact role journal image' USING ERRCODE='42501';END IF;\n  scanned:=scanned+(move_checks->>'rows')::integer;reads:=reads+(move_checks->>'reads')::integer;\n  move_extension:=kaname._authority_role_move_sequence_extend_v1(move_frozen,jsonb_array_length(maximum),p_rows-scanned,p_reads-reads);\n  scanned:=scanned+(move_extension->>'rows')::integer;reads:=reads+(move_extension->>'reads')::integer;\n  access_label_frozen:=jsonb_build_object('mode','selector_move')||access_label_frozen||jsonb_build_object(\n   'selector_move',move_frozen,'selector_move_fixed',jsonb_array_length(maximum),'selector_move_outputs',move_extension->'outputs');\n  maximum:=maximum||(move_extension->'slots');\n END IF;\n cost:=kaname._authority_sequence_reserve_v3('role',maximum,p_reads-reads);",
  " cost:=kaname._authority_sequence_reserve_v3('role',maximum,p_reads-reads);"
 ],
 [
  " access_label_authority_input jsonb;access_label_authority jsonb;\n move_checks jsonb;move_frozen jsonb;move_extension jsonb;",
  " access_label_authority_input jsonb;access_label_authority jsonb;"
 ]
]$pairs$::jsonb),
  ('authority_role_sequence_finalize_v3()','_authority_role_move_sequence_finalize_v1(jsonb,integer,integer)','_authority_role_move_sequence_finalize_v1(p_copies jsonb,p_rows integer,p_reads integer)','0adfc241154b42e561425452f8ceef42eeefa3e802a21111e9e74d5a434830cd','6f0700709a8b82c29973349ae74232b9d1ae57bfb5bf2002fa26432f05efbedf','f500d728c4214be2015a5d7f6ed07c5dc98172fcc0249a98ae56c65a57c51f67',$wrapper$
BEGIN
 PERFORM kaname._authority_role_move_sequence_finalize_v1(NULL,NULL,NULL);
END $wrapper$,$pairs$[
 [
  "\n RETURN move_cost;\nEND",
  "\nEND"
 ],
 [
  " IF (program->'frozen') ? 'selector_move' THEN\n  IF p_copies IS NULL THEN\n   RAISE EXCEPTION 'selector move requires its private decision' USING ERRCODE='42501';END IF;\n  move_cost:=kaname._authority_role_move_sequence_publish_v1(p_copies,p_rows,p_reads);\n ELSE\n  IF p_copies IS NOT NULL THEN\n   RAISE EXCEPTION 'selector move requires its own frozen program' USING ERRCODE='42501';END IF;\n SELECT coalesce(array_agg((value->>'ordinal')::integer ORDER BY (value->>'ordinal')::integer),ARRAY[]::integer[]) INTO ordinals\n FROM jsonb_array_elements(program->'maximum')\n WHERE program#>>ARRAY['frozen','expiry',value->>'ordinal'] IS NULL\n  OR (program#>>ARRAY['frozen','expiry',value->>'ordinal'])::timestamptz>at_time;\n PERFORM kaname._authority_sequence_select_v3(ordinals,at_time);\n END IF;\n",
  " SELECT coalesce(array_agg((value->>'ordinal')::integer ORDER BY (value->>'ordinal')::integer),ARRAY[]::integer[]) INTO ordinals\n FROM jsonb_array_elements(program->'maximum')\n WHERE program#>>ARRAY['frozen','expiry',value->>'ordinal'] IS NULL\n  OR (program#>>ARRAY['frozen','expiry',value->>'ordinal'])::timestamptz>at_time;\n PERFORM kaname._authority_sequence_select_v3(ordinals,at_time);\n"
 ],
 [
  " move_cost jsonb;required_questions jsonb;",
  " required_questions jsonb;"
 ]
]$pairs$::jsonb)
 ) AS x(public_signature,private_signature,private_parameters,original_hash,private_hash,wrapper_hash,wrapper,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.public_signature);
  SELECT prosrc,pg_get_functiondef(oid) INTO STRICT old_body,definition FROM pg_proc
   WHERE oid=fn AND proowner=current_user::regrole AND prosecdef;
  IF length(definition)-length(replace(definition,old_body,''))<>length(old_body)
   OR encode(sha256(convert_to(old_body,'UTF8')),'hex') IS DISTINCT FROM item.wrapper_hash THEN
   RAISE EXCEPTION 'changed role sequence wrapper %',item.public_signature USING ERRCODE='55000';END IF;
  SELECT prosrc INTO STRICT body FROM pg_proc WHERE oid=to_regprocedure('kaname.'||item.private_signature)
   AND proowner=current_user::regrole AND NOT prosecdef;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.private_hash THEN
   RAISE EXCEPTION 'changed private role sequence compiler %',item.private_signature USING ERRCODE='55000';END IF;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF length(body)-length(replace(body,pair->>0,''))<>length(pair->>0) THEN
    RAISE EXCEPTION 'role compiler fragment is not unique' USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.original_hash THEN
   RAISE EXCEPTION 'changed restored role sequence compiler' USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,old_body,body);
 END LOOP;
END;
$compile$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $repin$
DECLARE item record; fn regprocedure; prior_body text; body text; definition text; source_literal text; pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('authority_metadata_service_account_access_label_ready_v1()','ddd528b7365fd23685693207053e82a4fba204d2eb55d61f87506889a78c5559','042ab86ea4d7d0f9deaf4989efa5a51efd43bb8fac1cdcf4ad135ab35d9e5ad7',$pairs$[
 [
  "69b30e1a511507c6d0e27a5e3b0eeb71d2302504e0bd884c01646e134c20d59f",
  "250c74cf3b696e3337a4845f38d748384e524448cd86872fcaf59f2a6961c841"
 ],
 [
  "3b2369bd73c9e96a3a2a7825ec68f7ea11b14eaa6a13797c49ef2cf1f3904410",
  "0217a266427178ae68d624340325b5bbd2e8d9d939377db1bebb5396b6af5093"
 ]
]$pairs$::jsonb),
  ('_authority_full_contract_storage_v3()','69b30e1a511507c6d0e27a5e3b0eeb71d2302504e0bd884c01646e134c20d59f','250c74cf3b696e3337a4845f38d748384e524448cd86872fcaf59f2a6961c841',$pairs$[
 [
  "3b2369bd73c9e96a3a2a7825ec68f7ea11b14eaa6a13797c49ef2cf1f3904410",
  "0217a266427178ae68d624340325b5bbd2e8d9d939377db1bebb5396b6af5093"
 ]
]$pairs$::jsonb),
  ('_authority_crud_storage_v3()','3b2369bd73c9e96a3a2a7825ec68f7ea11b14eaa6a13797c49ef2cf1f3904410','0217a266427178ae68d624340325b5bbd2e8d9d939377db1bebb5396b6af5093',$pairs$[
 [
  "  ('_authority_resource_selector_matches_v3(jsonb,text,text,jsonb,jsonb)','boolean',5,ARRAY['p_selector','p_type','p_id','p_labels','p_access_labels']),\n  ('_authority_role_move_copy_registry_hold_v1()','void',0,NULL::text[]),\n  ('_authority_role_move_iam_copy_sources_hold_v1(text,text,jsonb,jsonb,text,text,integer,integer)','jsonb',8,ARRAY['p_root_type','p_root_id','p_expected','p_access_labels','p_actor_type','p_actor_id','p_rows','p_reads']),\n  ('_authority_role_move_external_copy_sources_hold_v1(text,text,jsonb,jsonb,text,text,integer,integer)','jsonb',8,ARRAY['p_root_type','p_root_id','p_expected','p_access_labels','p_actor_type','p_actor_id','p_rows','p_reads']),\n  ('_authority_role_move_copy_requirements_hold_v1(jsonb,text,text,integer,integer)','jsonb',5,ARRAY['p_plan','p_actor_type','p_actor_id','p_rows','p_reads']),\n  ('_authority_role_move_copy_requirements_require_v1(jsonb,jsonb,text,text,timestamptz,integer,integer)','jsonb',7,ARRAY['p_held','p_copies','p_actor_type','p_actor_id','p_at','p_rows','p_reads']),\n  ('_authority_role_move_role_image_hold_v1(text,text,jsonb,jsonb,jsonb,integer,integer)','jsonb',7,ARRAY['p_role_id','p_version','p_expected','p_moves','p_proposed_rules','p_rows','p_reads']),\n  ('_authority_role_move_attestation_v1()','jsonb',0,NULL::text[]),\n  ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_input','p_actor','p_rows','p_reads']),\n  ('_authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_frozen','p_copies','p_rows','p_reads']),\n  ('_authority_role_move_root_journal_v1(jsonb,integer)','jsonb',2,ARRAY['p_command','p_ordinal']),\n  ('_authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer)','jsonb',4,ARRAY['p_frozen','p_fixed','p_rows','p_reads']),\n  ('_authority_role_move_sequence_publish_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_copies','p_rows','p_reads']),\n  ('_authority_role_move_sequence_approve_v1()','void',0,NULL::text[]),\n  ('_authority_role_move_sequence_prepare_v1(jsonb,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_input','p_move','p_actor','p_rows','p_reads']),\n  ('_authority_role_move_sequence_finalize_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_copies','p_rows','p_reads']),",
  "  ('_authority_resource_selector_matches_v3(jsonb,text,text,jsonb,jsonb)','boolean',5,ARRAY['p_selector','p_type','p_id','p_labels','p_access_labels']),"
 ],
 [
  " ('_authority_role_actor_revoke_grants_v1(oid)','9be92689be1bda5db54c954b756f88eccef63d5fdb73de2a9d121c0629b15e86',false,'v',true,'private'),\n ('_authority_role_move_copy_registry_hold_v1()','926d2d998342fd05106c52603aa78142f6a8ce73f4d3c7699fa6d4981db1967e',false,'v',true,'private'),\n ('_authority_role_move_iam_copy_sources_hold_v1(text,text,jsonb,jsonb,text,text,integer,integer)','99c34be6e35ca9b1b1b97ea0c16f6c1b4768c3c000d3613136ac9f1f9a5cdbea',false,'v',true,'private'),\n ('_authority_role_move_external_copy_sources_hold_v1(text,text,jsonb,jsonb,text,text,integer,integer)','46e5c2961173bfc399aed60bf270aab42d5c74215e7dc18d4be429356c1bca8e',false,'v',true,'private'),\n ('_authority_role_move_copy_requirements_hold_v1(jsonb,text,text,integer,integer)','3ad9612a52ef6d3d615c94439e62dfb7a1da6d545cec876867389a718cba4576',false,'v',true,'private'),\n ('_authority_role_move_copy_requirements_require_v1(jsonb,jsonb,text,text,timestamptz,integer,integer)','c92e9a006c88a0e30be5ba01b6a2396762de4e2033c685845746e7e309906829',false,'v',true,'private'),\n ('_authority_role_move_role_image_hold_v1(text,text,jsonb,jsonb,jsonb,integer,integer)','c1c04a83e4a4ce0b5f09a13d1aedf91874e7734ab1aef1a414a603e194c394eb',false,'v',true,'private'),\n ('_authority_role_move_attestation_v1()','2db733815c857aad263cfcd93407e86f4594d28b808d569ca075e540005901af',false,'v',true,'private'),\n ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','b62b3fed95dfd39408adf6086649d034fa1fdc39bcc6c7c406ea94e278e34804',false,'v',true,'private'),\n ('_authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)','9644399436d2dca53ab8f629522a88abe0aa16f06eb856b616abd79e73a38927',false,'v',true,'private'),\n ('_authority_role_move_root_journal_v1(jsonb,integer)','19eade41e3bd6c1673dc5a739143c335d67957af1c9a8b66ba2e847708506746',false,'s',true,'private'),\n ('_authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer)','a61a057c02720031cd029075490eb56a6cacabbca9bc18ef1e7d27463a40c577',false,'v',true,'private'),\n ('_authority_role_move_sequence_publish_v1(jsonb,integer,integer)','09b3bbd42c75e5a01bec9fd1b0829b9604e32a3de35ec777ce411e3bb50ff213',false,'v',true,'private'),\n ('_authority_role_move_sequence_approve_v1()','68bf1bae5828e05864b7d6b27986abb0a2123d573f534ddc8e938f7045bdcb7c',false,'v',true,'private'),\n ('_authority_role_move_sequence_prepare_v1(jsonb,jsonb,jsonb,integer,integer)','157d289b31d5bb2e1901df54ef5b60e9c08ace47518da56e0ffdff80c4c4a9fc',false,'v',true,'private'),\n ('_authority_role_move_sequence_finalize_v1(jsonb,integer,integer)','6f0700709a8b82c29973349ae74232b9d1ae57bfb5bf2002fa26432f05efbedf',false,'v',true,'private'),",
  " ('_authority_role_actor_revoke_grants_v1(oid)','9be92689be1bda5db54c954b756f88eccef63d5fdb73de2a9d121c0629b15e86',false,'v',true,'private'),"
 ],
 [
  "319c4cda0e3e509c803b5429e1184baaf105a1fbdf02b08d833646a193ae02f4",
  "ea51295fc9a86b810572e9400319ae8defec75a270ef20b5ed1ce68acd5a9915"
 ],
 [
  "8ea1d2e5e9216e08e479cccb484722d3e78e121cdeda01c030062a99cdee4338",
  "1a76eb48aa2c75c7213b7e01fe7530bfe859348a0fb8cf3cb0d79be83e9dd1f8"
 ],
 [
  "f500d728c4214be2015a5d7f6ed07c5dc98172fcc0249a98ae56c65a57c51f67",
  "0adfc241154b42e561425452f8ceef42eeefa3e802a21111e9e74d5a434830cd"
 ],
 [
  "a2f5785344e6e53ce74cc1eafb3fcc8e234956b90837e010d70803d9f146061e",
  "0890abdfa2517000901077218dde1cbe48b465003ce4c8e5e74559a2ebaa167e"
 ]
]$pairs$::jsonb),
  ('authority_role_sequence_stamp_v3(jsonb)','8ea1d2e5e9216e08e479cccb484722d3e78e121cdeda01c030062a99cdee4338','1a76eb48aa2c75c7213b7e01fe7530bfe859348a0fb8cf3cb0d79be83e9dd1f8',$pairs$[
 [
  " IF (program->'frozen') ? 'selector_move' AND (\n  jsonb_typeof(program#>'{frozen,selector_move_approved}') IS DISTINCT FROM 'object'\n  OR program#>'{frozen,selector_move_approved,nonce}' IS DISTINCT FROM program->'nonce'\n  OR program#>'{frozen,selector_move_approved,actor}' IS DISTINCT FROM program#>'{frozen,selector_move,actor}'\n  OR program#>'{frozen,selector_move_approved,role_id}' IS DISTINCT FROM program#>'{frozen,id}'\n  OR (program#>>'{frozen,selector_move_approved,decision_at}')::timestamptz IS DISTINCT FROM (program->>'decision_at')::timestamptz) THEN\n  RAISE EXCEPTION 'selector move role stamp requires approval' USING ERRCODE='42501';END IF;\n RETURN (program#>>'{frozen,stamp}')::timestamptz;",
  " RETURN (program#>>'{frozen,stamp}')::timestamptz;"
 ]
]$pairs$::jsonb),
  ('_authority_sequence_complete_v3()','319c4cda0e3e509c803b5429e1184baaf105a1fbdf02b08d833646a193ae02f4','ea51295fc9a86b810572e9400319ae8defec75a270ef20b5ed1ce68acd5a9915',$pairs$[
 [
  " IF program->>'family'='role' AND program#>>'{frozen,mode}' IN ('selector_move','access_label_transition') THEN\n  IF EXISTS(SELECT FROM pg_temp.kaname_authority_sequence_program s WHERE s.singleton AND s.frozen ? 'selector_move'\n   AND (jsonb_typeof(s.frozen->'selector_move_approved') IS DISTINCT FROM 'object'\n    OR jsonb_typeof(s.frozen#>'{selector_move_decision,commands}') IS DISTINCT FROM 'array'\n    OR (s.frozen#>'{selector_move_decision,commands}'<>'[]'::jsonb AND s.frozen->'selector_move_roots_completed'\n      IS DISTINCT FROM to_jsonb(jsonb_array_length(s.frozen#>'{selector_move_decision,commands}')))) ) THEN\n   RAISE EXCEPTION 'selector move approval or root completion is absent' USING ERRCODE='42501';END IF;\n END IF;\n IF program->>'family'='metadata' AND program#>>'{frozen,mode}' IN ('external_ordinary','external_noop') THEN",
  " IF program->>'family'='metadata' AND program#>>'{frozen,mode}' IN ('external_ordinary','external_noop') THEN"
 ]
]$pairs$::jsonb)
 ) AS pins(signature,before_hash,after_hash,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT prior_body,definition FROM pg_catalog.pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(prior_body,'UTF8')),'hex') IS DISTINCT FROM item.before_hash THEN
   RAISE EXCEPTION 'Исходное тело функции % изменилось',item.signature USING ERRCODE='55000';
  END IF;
  body:=prior_body;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF length(body)-length(replace(body,pair->>0,''))<>length(pair->>0) THEN
    RAISE EXCEPTION 'Фрагмент тела функции % не уникален',item.signature USING ERRCODE='55000';
   END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.after_hash
   OR length(definition)-length(replace(definition,prior_body,''))<>length(prior_body) THEN
   RAISE EXCEPTION 'Расчётный образ функции % изменился',item.signature USING ERRCODE='55000';
  END IF;
  source_literal:=substring(left(definition,strpos(definition,prior_body)-1)
   FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||prior_body||source_literal)=0 THEN
   RAISE EXCEPTION 'Не найден литерал тела функции %',item.signature USING ERRCODE='55000';
  END IF;
  EXECUTE replace(definition,source_literal||prior_body||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
     IS DISTINCT FROM item.after_hash THEN
   RAISE EXCEPTION 'Установленное тело функции % изменилось',item.signature USING ERRCODE='55000';
  END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'Нарушена целостность контракта записи' USING ERRCODE='55000';
 END IF;
END;
$repin$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_role_move_sequence_finalize_v1(jsonb,integer,integer);
DROP FUNCTION kaname._authority_role_move_sequence_prepare_v1(jsonb,jsonb,jsonb,integer,integer);
DROP FUNCTION kaname._authority_role_move_sequence_approve_v1();
DROP FUNCTION kaname._authority_role_move_sequence_publish_v1(jsonb,integer,integer);
DROP FUNCTION kaname._authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer);
DROP FUNCTION kaname._authority_role_move_root_journal_v1(jsonb,integer);
