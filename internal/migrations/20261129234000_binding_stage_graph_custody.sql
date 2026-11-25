-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Один и тот же закрытый снимок физических таблиц, опорных ключей и двух
-- живых моделей проверяется сначала в RR, затем до резерва в транзакции записи.
CREATE FUNCTION kaname._authority_binding_project_graph_custody_v1(p_invoker oid,p_reserve boolean,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $custody$
DECLARE
    sources jsonb:='[]'::jsonb;models jsonb:='{}'::jsonb;catalog_rows jsonb:='[]'::jsonb;
    spec record;witness jsonb;images jsonb;dotted_name text;mapped text;
    row_cost constant integer:=64;read_cost constant integer:=20;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN row_cost AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN read_cost AND 4096 THEN
        RAISE EXCEPTION 'binding native project custody exceeds budget' USING ERRCODE='54000';END IF;
    IF p_invoker IS NULL OR p_reserve IS NULL OR current_setting('transaction_isolation') IS DISTINCT FROM
        (CASE WHEN p_reserve THEN 'read committed' ELSE 'repeatable read' END) THEN
        RAISE EXCEPTION 'binding native project custody phase differs' USING ERRCODE='42501';END IF;
    IF p_reserve THEN
        IF EXISTS(SELECT FROM unnest(ARRAY['kaname.catalog_resource'::regclass,'kaname.resource_mirror'::regclass,
            'kaname.resource_parent_edge'::regclass,'kaname.projects'::regclass,'kaname.accounts'::regclass]) t(oid)
            WHERE has_table_privilege(p_invoker,t.oid,'SELECT') IS DISTINCT FROM true) THEN
            RAISE EXCEPTION 'binding native project reader privilege changed' USING ERRCODE='42501';END IF;
        -- Участник уже удерживает глобальную запись epoch. NOWAIT сохраняет
        -- повтор всей попытки при незавершённом DDL или записи физического графа.
        LOCK TABLE ONLY kaname.catalog_resource, ONLY kaname.resource_mirror, ONLY kaname.resource_parent_edge,
            ONLY kaname.projects, ONLY kaname.accounts IN SHARE MODE NOWAIT;
    END IF;
    FOR spec IN SELECT * FROM (VALUES
        ('kaname.catalog_resource'::regclass,'catalog_resource_dotted_live_uk',ARRAY['dotted','live']),
        ('kaname.catalog_resource'::regclass,'catalog_resource_object_type_live_uk',ARRAY['object_type','live']),
        ('kaname.resource_mirror'::regclass,'resource_mirror_pkey',ARRAY['object_type','object_id']),
        ('kaname.resource_parent_edge'::regclass,'resource_parent_edge_pkey',ARRAY['object_type','object_id','depth']),
        ('kaname.projects'::regclass,'projects_pkey',ARRAY['id']),('kaname.accounts'::regclass,'accounts_pkey',ARRAY['id'])
    ) keys(rel,keyname,cols) ORDER BY keyname COLLATE "C" LOOP
        SELECT jsonb_build_array(c.oid,c.relowner,c.relnamespace,c.relfilenode,c.xmin::text,c.ctid::text,
            encode(sha256(convert_to(coalesce(c.relacl::text,''),'UTF8')),'hex'),k.oid,k.xmin::text,k.ctid::text,
            idx.oid,idx.relfilenode,i.xmin::text,i.ctid::text)
        INTO witness FROM pg_class c
        JOIN pg_constraint k ON k.conrelid=c.oid AND k.conname=spec.keyname AND k.contype IN ('p','u')
        JOIN pg_index i ON i.indexrelid=k.conindid AND i.indrelid=c.oid
        JOIN pg_class idx ON idx.oid=i.indexrelid AND idx.relkind='i' AND idx.relowner=c.relowner
        JOIN pg_am am ON am.oid=idx.relam AND am.amname='btree'
        WHERE c.oid=spec.rel AND c.relowner=current_user::regrole AND c.relkind='r' AND c.relpersistence='p'
          AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relispartition OR c.relhasrules)
          AND NOT EXISTS(SELECT FROM pg_inherits h WHERE h.inhparent=c.oid OR h.inhrelid=c.oid)
          AND has_table_privilege(p_invoker,c.oid,'SELECT') AND coalesce(pg_column_size(c.relacl),0)<=1048576
          AND k.convalidated AND NOT (k.condeferrable OR k.condeferred)
          AND i.indisunique AND i.indisvalid AND i.indisready AND i.indimmediate AND i.indislive
          AND i.indpred IS NULL AND i.indexprs IS NULL AND i.indnkeyatts=cardinality(spec.cols)
          AND (SELECT array_agg(a.attname::text ORDER BY n.pos) FROM unnest(i.indkey::smallint[]) WITH ORDINALITY n(num,pos)
                JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=n.num AND NOT a.attisdropped
                WHERE n.pos<=i.indnkeyatts)=spec.cols;
        IF witness IS NULL THEN RAISE EXCEPTION 'binding native project relation or key custody differs' USING ERRCODE='42501';END IF;
        sources:=sources||jsonb_build_array(witness);
    END LOOP;
    FOREACH dotted_name IN ARRAY ARRAY['iam.account','iam.project'] LOOP
        -- В staged Go reader имя ищется по dotted или model name. Чужая
        -- живая строка, совпадающая по второму ключу, делает выбор неоднозначным.
        SELECT coalesce(jsonb_agg(row_image),'[]'::jsonb) INTO images FROM (
            SELECT jsonb_build_array(c.tableoid,c.xmin::text,c.ctid::text,CASE WHEN c.dotted=dotted_name THEN dotted_name END,
                CASE WHEN octet_length(c.object_type) BETWEEN 1 AND 16384 THEN c.object_type END,
                CASE WHEN c.module='iam' THEN 'iam' END) AS row_image
            FROM ONLY kaname.catalog_resource c WHERE c.live AND (c.dotted=dotted_name OR c.object_type=dotted_name) LIMIT 2
        ) candidate;
        mapped:=images#>>'{0,4}';
        IF jsonb_array_length(images)<>1 OR images#>>'{0,3}' IS DISTINCT FROM dotted_name
            OR images#>>'{0,5}' IS DISTINCT FROM 'iam' OR coalesce(octet_length(mapped),0) NOT BETWEEN 1 AND 16384
            OR mapped ~ '[:#*[:space:][:cntrl:]]' THEN
            RAISE EXCEPTION 'binding native project catalog model is missing or ambiguous' USING ERRCODE='42501';END IF;
        catalog_rows:=catalog_rows||images;models:=models||jsonb_build_object(dotted_name,mapped);
    END LOOP;
    IF models->>'iam.account'=models->>'iam.project' THEN
        RAISE EXCEPTION 'binding native project models overlap' USING ERRCODE='42501';END IF;
    RETURN jsonb_build_object('source',jsonb_build_object('tables',sources,'catalog',catalog_rows,'models',models),
        'rows',row_cost,'reads',read_cost);
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'binding native project storage is changing' USING ERRCODE='40001';
END;
$custody$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure:='kaname._authority_binding_project_graph_custody_v1(oid,boolean,integer,integer)'::regprocedure;grantee record;
BEGIN
    FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_proc p
        CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        LEFT JOIN pg_roles r ON r.oid=a.grantee WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
            CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $storage$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)','d198f5d173014c7c7197f6e1987b9cd96cf2588597e1ce562604c3b42ad6e284','995cf5d3e2dd30a4851d6b6c3bd26cfa1b4f6b2404e5219daeedaadb6bc09778',$edits$[
 [
  "physical_models jsonb;catalog_models jsonb;",
  "physical_models jsonb;project_custody jsonb;custody_step jsonb;matches jsonb;wanted text;"
 ],
 [
  " IF role_projection->'nested_project'='true'::jsonb THEN\n  -- Все источники проверены в одном RR snapshot. Без наследования их\n  -- xmin/ctid однозначно принадлежат родной таблице. Каталог дополнительно\n  -- связывает оба model type с фактическими строками и закреплённым bundle.\n  used_rows:=used_rows+10+jsonb_array_length(catalog#>'{Live,Resources}');used_reads:=used_reads+2;\n  IF used_rows>p_rows OR used_reads>p_reads THEN RAISE EXCEPTION 'binding nested graph custody exceeds budget' USING ERRCODE='54000';END IF;\n  IF EXISTS(SELECT FROM unnest(ARRAY['kaname.catalog_resource'::regclass,'kaname.resource_mirror'::regclass,\n   'kaname.resource_parent_edge'::regclass,'kaname.accounts'::regclass,'kaname.projects'::regclass]) src(oid)\n   WHERE NOT EXISTS(SELECT FROM pg_class c WHERE c.oid=src.oid AND c.relowner=owner_oid AND c.relkind='r' AND c.relpersistence='p'\n    AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relispartition OR c.relhasrules))\n    OR EXISTS(SELECT FROM pg_inherits i WHERE i.inhparent=src.oid OR i.inhrelid=src.oid)\n    OR NOT has_table_privilege(invoker,src.oid,'SELECT')) THEN\n   RAISE EXCEPTION 'binding nested graph physical source custody differs' USING ERRCODE='42501';END IF;\n  SELECT jsonb_object_agg(c.dotted,c.object_type) INTO physical_models FROM ONLY kaname.catalog_resource c\n   WHERE c.live AND c.module='iam' AND c.dotted IN ('iam.account','iam.project');\n  SELECT jsonb_object_agg('iam.'||(v->>'Resource'),v->'ObjectType') INTO catalog_models\n   FROM jsonb_array_elements(catalog#>'{Live,Resources}') v WHERE v->>'Module'='iam' AND v->>'Resource' IN ('account','project');\n  IF physical_models IS NULL OR NOT (physical_models ?& ARRAY['iam.account','iam.project'])\n   OR physical_models IS DISTINCT FROM catalog_models THEN\n   RAISE EXCEPTION 'binding nested project model mapping differs' USING ERRCODE='42501';END IF;\n END IF;\n",
  " IF role_projection->'nested_project'='true'::jsonb THEN\n  custody_step:=kaname._authority_binding_project_graph_custody_v1(invoker,false,p_rows-used_rows,p_reads-used_reads);\n  used_rows:=used_rows+(custody_step->>'rows')::integer;used_reads:=used_reads+(custody_step->>'reads')::integer;\n  project_custody:=custody_step->'source';physical_models:=project_custody->'models';\n  used_rows:=used_rows+2*jsonb_array_length(catalog#>'{Live,Resources}')+4;\n  IF used_rows>p_rows THEN RAISE EXCEPTION 'binding native project catalog exceeds budget' USING ERRCODE='54000';END IF;\n  FOREACH wanted IN ARRAY ARRAY['account','project'] LOOP\n   SELECT coalesce(jsonb_agg(v),'[]'::jsonb) INTO matches FROM (\n    SELECT jsonb_build_array(r->'Module',r->'Resource',r->'ObjectType') AS v\n    FROM jsonb_array_elements(catalog#>'{Live,Resources}') r\n    WHERE (r->>'Module'='iam' AND r->>'Resource'=wanted) OR r->'ObjectType'=physical_models->('iam.'||wanted) LIMIT 2\n   ) candidates;\n   IF matches IS DISTINCT FROM jsonb_build_array(jsonb_build_array('iam',wanted,physical_models->('iam.'||wanted))) THEN\n    RAISE EXCEPTION 'binding native project bundle mapping is missing or ambiguous' USING ERRCODE='42501';END IF;\n  END LOOP;\n END IF;\n"
 ],
 [
  "maximum jsonb NOT NULL,mirror jsonb,locked_xid",
  "maximum jsonb NOT NULL,mirror jsonb,project_graph_custody jsonb,locked_xid"
 ],
 [
  "accounts,epochs,expires_at,commands,maximum,mirror)",
  "accounts,epochs,expires_at,commands,maximum,mirror,project_graph_custody)"
 ],
 [
  "::timestamptz,commands,maximum,mirror);",
  "::timestamptz,commands,maximum,mirror,project_custody);"
 ]
]$edits$::jsonb),
        ('authority_binding_stage_sequence_prepare_v3(text,text[],jsonb,integer,integer)','efdbe3e491e0c3bd8ade664a61d8e049094cc5b781f7fe14347a94e2dd5979e6','1794be72bd1465da0730c854459d9550544605665ac5ef49a1919c5c7f9fbbfe',$edits$[
 [
  "mirror_cost record;",
  "mirror_cost record;custody jsonb;custody_reads integer:=0;"
 ],
 [
  " SELECT * INTO STRICT mirror_cost FROM kaname._authority_binding_mirror_prepare_v3(snapshot,p_rows-count_rows,p_reads-2);",
  " IF NOT (snapshot ? 'project_graph_custody') THEN\n  RAISE EXCEPTION 'binding stage captured before native graph custody installation' USING ERRCODE='40001';END IF;\n IF snapshot->'project_graph_custody'<>'null'::jsonb THEN\n  IF p_accounts IS NOT NULL OR proof->>'mode' IS DISTINCT FROM 'global' THEN\n   RAISE EXCEPTION 'binding native graph requires its signed global epoch' USING ERRCODE='42501';END IF;\n  custody:=kaname._authority_binding_project_graph_custody_v1((proof->>'invoker_oid')::oid,true,p_rows-count_rows,p_reads-2);\n  IF snapshot->'project_graph_custody' IS DISTINCT FROM custody->'source' THEN\n   RAISE EXCEPTION 'binding native graph custody changed before sequence reservation' USING ERRCODE='40001';END IF;\n  count_rows:=count_rows+(custody->>'rows')::integer;custody_reads:=(custody->>'reads')::integer;\n END IF;\n SELECT * INTO STRICT mirror_cost FROM kaname._authority_binding_mirror_prepare_v3(snapshot,p_rows-count_rows,p_reads-2-custody_reads);"
 ],
 [
  "snapshot->'maximum',p_reads-2-mirror_cost.logical_reads",
  "snapshot->'maximum',p_reads-2-custody_reads-mirror_cost.logical_reads"
 ],
 [
  "RETURN QUERY SELECT count_rows,used+2+mirror_cost.logical_reads;",
  "RETURN QUERY SELECT count_rows,used+2+custody_reads+mirror_cost.logical_reads;"
 ]
]$edits$::jsonb),
        ('_authority_crud_storage_v3()','922ae298a69359b8df896d84971ba69afa89bd75f4f5e78c76e17a7b2d3277e6','3e26f0d8f46bfe0bc4dc3e8b20a7a9598c10824b1ff57599fc21afa250e97cd5',$edits$[
 [
  "d198f5d173014c7c7197f6e1987b9cd96cf2588597e1ce562604c3b42ad6e284",
  "995cf5d3e2dd30a4851d6b6c3bd26cfa1b4f6b2404e5219daeedaadb6bc09778"
 ],
 [
  "efdbe3e491e0c3bd8ade664a61d8e049094cc5b781f7fe14347a94e2dd5979e6",
  "1794be72bd1465da0730c854459d9550544605665ac5ef49a1919c5c7f9fbbfe"
 ],
 [
  " ('_authority_role_move_nested_positions_v1(text,integer,integer)','1b96f2cd3f41db997fdc59449c038e26ff94e09cce1f40a301263e0763730aa1',false,'v',true,'private'),\n",
  " ('_authority_role_move_nested_positions_v1(text,integer,integer)','1b96f2cd3f41db997fdc59449c038e26ff94e09cce1f40a301263e0763730aa1',false,'v',true,'private'),\n ('_authority_binding_project_graph_custody_v1(oid,boolean,integer,integer)','e92c75b882df4b0b913cab2bb8b973e23772ffbf0fcac92977b9afa1a8a7f777',false,'v',true,'private'),\n"
 ],
 [
  "  ('_authority_role_move_nested_positions_v1(text,integer,integer)','jsonb',3,ARRAY['p_binding_id','p_rows','p_reads']),\n",
  "  ('_authority_role_move_nested_positions_v1(text,integer,integer)','jsonb',3,ARRAY['p_binding_id','p_rows','p_reads']),\n  ('_authority_binding_project_graph_custody_v1(oid,boolean,integer,integer)','jsonb',4,ARRAY['p_invoker','p_reserve','p_rows','p_reads']),\n"
 ]
]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','fc6c7393f0d22d82d795726acb153e3d78fcd9db461b09bd43e0a1ca8c2a00fa','ea96a7b7a34af312cead751c9ee8a54de914b4004ebbdd14676082abd795ed16',$edits$[
 [
  "922ae298a69359b8df896d84971ba69afa89bd75f4f5e78c76e17a7b2d3277e6",
  "3e26f0d8f46bfe0bc4dc3e8b20a7a9598c10824b1ff57599fc21afa250e97cd5"
 ]
]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','592b95d51bd7f3e75fd976a67f938a848420c6c6006b189655f2a455e3d7e55a','0c601a5c9b6a2370bb482d23a46ab2c973a88b1313d93598a781b8e78b502dac',$edits$[
 [
  "922ae298a69359b8df896d84971ba69afa89bd75f4f5e78c76e17a7b2d3277e6",
  "3e26f0d8f46bfe0bc4dc3e8b20a7a9598c10824b1ff57599fc21afa250e97cd5"
 ],
 [
  "fc6c7393f0d22d82d795726acb153e3d78fcd9db461b09bd43e0a1ca8c2a00fa",
  "ea96a7b7a34af312cead751c9ee8a54de914b4004ebbdd14676082abd795ed16"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','d2067328045b913de7a59d7012f3a43115bbb2546880a786fa44c22aa0e9130e','d3e61da2c5c7e258e019506cea5fdb884e265922fd4149ac8ce0259928dc9f8c',$edits$[
 [
  "fc6c7393f0d22d82d795726acb153e3d78fcd9db461b09bd43e0a1ca8c2a00fa",
  "ea96a7b7a34af312cead751c9ee8a54de914b4004ebbdd14676082abd795ed16"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','cc500d3cb15257e541a264b87f0cd8e82df5eddb2de254f76bce8a5e4aa7c05d','98dd9db5faa75bd513330519d03e4a4666f799847cd44349929b8912bb3e5273',$edits$[
 [
  "d2067328045b913de7a59d7012f3a43115bbb2546880a786fa44c22aa0e9130e",
  "d3e61da2c5c7e258e019506cea5fdb884e265922fd4149ac8ce0259928dc9f8c"
 ]
]$edits$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'staged native project physical custody predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'staged native project physical custody replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'staged native project physical custody body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'staged native project physical custody installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'staged native project physical custody storage graph differs' USING ERRCODE='55000';
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
        ('authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)','995cf5d3e2dd30a4851d6b6c3bd26cfa1b4f6b2404e5219daeedaadb6bc09778','d198f5d173014c7c7197f6e1987b9cd96cf2588597e1ce562604c3b42ad6e284',$edits$[
 [
  "::timestamptz,commands,maximum,mirror,project_custody);",
  "::timestamptz,commands,maximum,mirror);"
 ],
 [
  "accounts,epochs,expires_at,commands,maximum,mirror,project_graph_custody)",
  "accounts,epochs,expires_at,commands,maximum,mirror)"
 ],
 [
  "maximum jsonb NOT NULL,mirror jsonb,project_graph_custody jsonb,locked_xid",
  "maximum jsonb NOT NULL,mirror jsonb,locked_xid"
 ],
 [
  " IF role_projection->'nested_project'='true'::jsonb THEN\n  custody_step:=kaname._authority_binding_project_graph_custody_v1(invoker,false,p_rows-used_rows,p_reads-used_reads);\n  used_rows:=used_rows+(custody_step->>'rows')::integer;used_reads:=used_reads+(custody_step->>'reads')::integer;\n  project_custody:=custody_step->'source';physical_models:=project_custody->'models';\n  used_rows:=used_rows+2*jsonb_array_length(catalog#>'{Live,Resources}')+4;\n  IF used_rows>p_rows THEN RAISE EXCEPTION 'binding native project catalog exceeds budget' USING ERRCODE='54000';END IF;\n  FOREACH wanted IN ARRAY ARRAY['account','project'] LOOP\n   SELECT coalesce(jsonb_agg(v),'[]'::jsonb) INTO matches FROM (\n    SELECT jsonb_build_array(r->'Module',r->'Resource',r->'ObjectType') AS v\n    FROM jsonb_array_elements(catalog#>'{Live,Resources}') r\n    WHERE (r->>'Module'='iam' AND r->>'Resource'=wanted) OR r->'ObjectType'=physical_models->('iam.'||wanted) LIMIT 2\n   ) candidates;\n   IF matches IS DISTINCT FROM jsonb_build_array(jsonb_build_array('iam',wanted,physical_models->('iam.'||wanted))) THEN\n    RAISE EXCEPTION 'binding native project bundle mapping is missing or ambiguous' USING ERRCODE='42501';END IF;\n  END LOOP;\n END IF;\n",
  " IF role_projection->'nested_project'='true'::jsonb THEN\n  -- Все источники проверены в одном RR snapshot. Без наследования их\n  -- xmin/ctid однозначно принадлежат родной таблице. Каталог дополнительно\n  -- связывает оба model type с фактическими строками и закреплённым bundle.\n  used_rows:=used_rows+10+jsonb_array_length(catalog#>'{Live,Resources}');used_reads:=used_reads+2;\n  IF used_rows>p_rows OR used_reads>p_reads THEN RAISE EXCEPTION 'binding nested graph custody exceeds budget' USING ERRCODE='54000';END IF;\n  IF EXISTS(SELECT FROM unnest(ARRAY['kaname.catalog_resource'::regclass,'kaname.resource_mirror'::regclass,\n   'kaname.resource_parent_edge'::regclass,'kaname.accounts'::regclass,'kaname.projects'::regclass]) src(oid)\n   WHERE NOT EXISTS(SELECT FROM pg_class c WHERE c.oid=src.oid AND c.relowner=owner_oid AND c.relkind='r' AND c.relpersistence='p'\n    AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relispartition OR c.relhasrules))\n    OR EXISTS(SELECT FROM pg_inherits i WHERE i.inhparent=src.oid OR i.inhrelid=src.oid)\n    OR NOT has_table_privilege(invoker,src.oid,'SELECT')) THEN\n   RAISE EXCEPTION 'binding nested graph physical source custody differs' USING ERRCODE='42501';END IF;\n  SELECT jsonb_object_agg(c.dotted,c.object_type) INTO physical_models FROM ONLY kaname.catalog_resource c\n   WHERE c.live AND c.module='iam' AND c.dotted IN ('iam.account','iam.project');\n  SELECT jsonb_object_agg('iam.'||(v->>'Resource'),v->'ObjectType') INTO catalog_models\n   FROM jsonb_array_elements(catalog#>'{Live,Resources}') v WHERE v->>'Module'='iam' AND v->>'Resource' IN ('account','project');\n  IF physical_models IS NULL OR NOT (physical_models ?& ARRAY['iam.account','iam.project'])\n   OR physical_models IS DISTINCT FROM catalog_models THEN\n   RAISE EXCEPTION 'binding nested project model mapping differs' USING ERRCODE='42501';END IF;\n END IF;\n"
 ],
 [
  "physical_models jsonb;project_custody jsonb;custody_step jsonb;matches jsonb;wanted text;",
  "physical_models jsonb;catalog_models jsonb;"
 ]
]$edits$::jsonb),
        ('authority_binding_stage_sequence_prepare_v3(text,text[],jsonb,integer,integer)','1794be72bd1465da0730c854459d9550544605665ac5ef49a1919c5c7f9fbbfe','efdbe3e491e0c3bd8ade664a61d8e049094cc5b781f7fe14347a94e2dd5979e6',$edits$[
 [
  "RETURN QUERY SELECT count_rows,used+2+custody_reads+mirror_cost.logical_reads;",
  "RETURN QUERY SELECT count_rows,used+2+mirror_cost.logical_reads;"
 ],
 [
  "snapshot->'maximum',p_reads-2-custody_reads-mirror_cost.logical_reads",
  "snapshot->'maximum',p_reads-2-mirror_cost.logical_reads"
 ],
 [
  " IF NOT (snapshot ? 'project_graph_custody') THEN\n  RAISE EXCEPTION 'binding stage captured before native graph custody installation' USING ERRCODE='40001';END IF;\n IF snapshot->'project_graph_custody'<>'null'::jsonb THEN\n  IF p_accounts IS NOT NULL OR proof->>'mode' IS DISTINCT FROM 'global' THEN\n   RAISE EXCEPTION 'binding native graph requires its signed global epoch' USING ERRCODE='42501';END IF;\n  custody:=kaname._authority_binding_project_graph_custody_v1((proof->>'invoker_oid')::oid,true,p_rows-count_rows,p_reads-2);\n  IF snapshot->'project_graph_custody' IS DISTINCT FROM custody->'source' THEN\n   RAISE EXCEPTION 'binding native graph custody changed before sequence reservation' USING ERRCODE='40001';END IF;\n  count_rows:=count_rows+(custody->>'rows')::integer;custody_reads:=(custody->>'reads')::integer;\n END IF;\n SELECT * INTO STRICT mirror_cost FROM kaname._authority_binding_mirror_prepare_v3(snapshot,p_rows-count_rows,p_reads-2-custody_reads);",
  " SELECT * INTO STRICT mirror_cost FROM kaname._authority_binding_mirror_prepare_v3(snapshot,p_rows-count_rows,p_reads-2);"
 ],
 [
  "mirror_cost record;custody jsonb;custody_reads integer:=0;",
  "mirror_cost record;"
 ]
]$edits$::jsonb),
        ('_authority_crud_storage_v3()','3e26f0d8f46bfe0bc4dc3e8b20a7a9598c10824b1ff57599fc21afa250e97cd5','922ae298a69359b8df896d84971ba69afa89bd75f4f5e78c76e17a7b2d3277e6',$edits$[
 [
  "  ('_authority_role_move_nested_positions_v1(text,integer,integer)','jsonb',3,ARRAY['p_binding_id','p_rows','p_reads']),\n  ('_authority_binding_project_graph_custody_v1(oid,boolean,integer,integer)','jsonb',4,ARRAY['p_invoker','p_reserve','p_rows','p_reads']),\n",
  "  ('_authority_role_move_nested_positions_v1(text,integer,integer)','jsonb',3,ARRAY['p_binding_id','p_rows','p_reads']),\n"
 ],
 [
  " ('_authority_role_move_nested_positions_v1(text,integer,integer)','1b96f2cd3f41db997fdc59449c038e26ff94e09cce1f40a301263e0763730aa1',false,'v',true,'private'),\n ('_authority_binding_project_graph_custody_v1(oid,boolean,integer,integer)','e92c75b882df4b0b913cab2bb8b973e23772ffbf0fcac92977b9afa1a8a7f777',false,'v',true,'private'),\n",
  " ('_authority_role_move_nested_positions_v1(text,integer,integer)','1b96f2cd3f41db997fdc59449c038e26ff94e09cce1f40a301263e0763730aa1',false,'v',true,'private'),\n"
 ],
 [
  "1794be72bd1465da0730c854459d9550544605665ac5ef49a1919c5c7f9fbbfe",
  "efdbe3e491e0c3bd8ade664a61d8e049094cc5b781f7fe14347a94e2dd5979e6"
 ],
 [
  "995cf5d3e2dd30a4851d6b6c3bd26cfa1b4f6b2404e5219daeedaadb6bc09778",
  "d198f5d173014c7c7197f6e1987b9cd96cf2588597e1ce562604c3b42ad6e284"
 ]
]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','ea96a7b7a34af312cead751c9ee8a54de914b4004ebbdd14676082abd795ed16','fc6c7393f0d22d82d795726acb153e3d78fcd9db461b09bd43e0a1ca8c2a00fa',$edits$[
 [
  "3e26f0d8f46bfe0bc4dc3e8b20a7a9598c10824b1ff57599fc21afa250e97cd5",
  "922ae298a69359b8df896d84971ba69afa89bd75f4f5e78c76e17a7b2d3277e6"
 ]
]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','0c601a5c9b6a2370bb482d23a46ab2c973a88b1313d93598a781b8e78b502dac','592b95d51bd7f3e75fd976a67f938a848420c6c6006b189655f2a455e3d7e55a',$edits$[
 [
  "ea96a7b7a34af312cead751c9ee8a54de914b4004ebbdd14676082abd795ed16",
  "fc6c7393f0d22d82d795726acb153e3d78fcd9db461b09bd43e0a1ca8c2a00fa"
 ],
 [
  "3e26f0d8f46bfe0bc4dc3e8b20a7a9598c10824b1ff57599fc21afa250e97cd5",
  "922ae298a69359b8df896d84971ba69afa89bd75f4f5e78c76e17a7b2d3277e6"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','d3e61da2c5c7e258e019506cea5fdb884e265922fd4149ac8ce0259928dc9f8c','d2067328045b913de7a59d7012f3a43115bbb2546880a786fa44c22aa0e9130e',$edits$[
 [
  "ea96a7b7a34af312cead751c9ee8a54de914b4004ebbdd14676082abd795ed16",
  "fc6c7393f0d22d82d795726acb153e3d78fcd9db461b09bd43e0a1ca8c2a00fa"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','98dd9db5faa75bd513330519d03e4a4666f799847cd44349929b8912bb3e5273','cc500d3cb15257e541a264b87f0cd8e82df5eddb2de254f76bce8a5e4aa7c05d',$edits$[
 [
  "d3e61da2c5c7e258e019506cea5fdb884e265922fd4149ac8ce0259928dc9f8c",
  "d2067328045b913de7a59d7012f3a43115bbb2546880a786fa44c22aa0e9130e"
 ]
]$edits$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'staged native project physical custody predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'staged native project physical custody replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'staged native project physical custody body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'staged native project physical custody installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'staged native project physical custody storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_binding_project_graph_custody_v1(oid,boolean,integer,integer);
