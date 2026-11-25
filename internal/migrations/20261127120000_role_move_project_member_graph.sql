-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Удерживает родной проект и точное состояние выбранного зеркала в транзакции роли.
CREATE FUNCTION kaname._authority_role_move_project_member_graph_hold_v1(
    p_project_id text,p_native jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $hold$
DECLARE
    proof jsonb;
    item record;
    project_model text;
    account_model text;
    catalog_rows jsonb:='[]'::jsonb;
    catalog_resources jsonb:='[]'::jsonb;
    edge_rows jsonb:='[]'::jsonb;
    native_row jsonb;
    mirror_row jsonb;
    captured jsonb:='{}'::jsonb;
    project_graph jsonb;
    receipt jsonb;
    used_bytes bigint;
    source_row jsonb;
    source_id text;
    parent_project text;
    used_rows integer:=11;
    used_reads integer:=4;
    seen_edges integer:=0;
BEGIN
    proof:=kaname._authority_role_move_attestation_v1();
    IF coalesce(p_project_id,'')='' OR octet_length(p_project_id)>16384
        OR p_project_id ~ '[:#*[:space:][:cntrl:]]'
        OR jsonb_typeof(p_native) IS DISTINCT FROM 'array'
        OR jsonb_array_length(p_native)<>3 THEN
        RAISE EXCEPTION 'invalid selector move project graph coordinates' USING ERRCODE='42501';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096
        OR octet_length(p_native::text)>8388608 THEN
        RAISE EXCEPTION 'selector move project graph input exceeds budget' USING ERRCODE='54000';
    END IF;
    -- Порядок совпадает с существующим удержанием переписи потомков роли.
    LOCK TABLE ONLY kaname.catalog_resource, ONLY kaname.resource_mirror, ONLY kaname.resource_parent_edge
        IN SHARE MODE NOWAIT;
    IF EXISTS(SELECT 1 FROM unnest(ARRAY['kaname.catalog_resource'::regclass,'kaname.resource_mirror'::regclass,
        'kaname.resource_parent_edge'::regclass,'kaname.projects'::regclass,'kaname.accounts'::regclass]) AS source(oid)
        WHERE NOT EXISTS(SELECT 1 FROM pg_class c WHERE c.oid=source.oid
            AND c.relowner=current_user::regrole AND c.relkind='r' AND c.relpersistence='p'
            AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relispartition OR c.relhasrules)
            AND NOT EXISTS(SELECT 1 FROM pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid))
            OR NOT has_table_privilege((proof->>'invoker_oid')::oid,source.oid,'SELECT')) THEN
        RAISE EXCEPTION 'selector move project graph source custody differs' USING ERRCODE='42501';
    END IF;
    IF EXISTS(SELECT 1 FROM (VALUES
        ('kaname.catalog_resource'::regclass,ARRAY['dotted','live']),
        ('kaname.resource_mirror'::regclass,ARRAY['object_type','object_id']),
        ('kaname.resource_parent_edge'::regclass,ARRAY['object_type','object_id','depth']),
        ('kaname.projects'::regclass,ARRAY['id']),('kaname.accounts'::regclass,ARRAY['id'])
    ) AS source(rel,cols)
    WHERE NOT EXISTS(SELECT 1 FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid
        JOIN pg_am am ON am.oid=idx.relam
        WHERE i.indrelid=source.rel AND am.amname='btree' AND i.indisready AND i.indisvalid
            AND i.indisunique AND i.indimmediate AND i.indpred IS NULL AND i.indexprs IS NULL
            AND (SELECT array_agg(a.attname::text ORDER BY k.pos)
                FROM unnest(i.indkey::smallint[]) WITH ORDINALITY AS k(attnum,pos)
                JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum
                WHERE k.pos<=i.indnkeyatts)=source.cols)) THEN
        RAISE EXCEPTION 'selector move project graph source keys differ' USING ERRCODE='42501';
    END IF;
    IF p_rows-used_rows<2 OR p_reads-used_reads<2 THEN
        RAISE EXCEPTION 'selector move project graph read budget exhausted' USING ERRCODE='54000';
    END IF;

    SELECT jsonb_build_array(p.xmin::text,p.ctid::text,to_jsonb(p)) INTO native_row
    FROM ONLY kaname.projects p WHERE p.id=p_project_id FOR SHARE OF p NOWAIT;
    SELECT jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) INTO mirror_row
    FROM ONLY kaname.resource_mirror m WHERE m.object_type='iam.project' AND m.object_id=p_project_id;
    IF native_row IS NULL OR native_row IS DISTINCT FROM p_native THEN
        RAISE EXCEPTION 'selector move physical project graph changed' USING ERRCODE='40001';
    END IF;
    used_bytes:=octet_length(native_row::text)+coalesce(octet_length(mirror_row::text),0);
    IF used_bytes>8388608 THEN
        RAISE EXCEPTION 'selector move project sources exceed byte budget' USING ERRCODE='54000';
    END IF;
    used_rows:=used_rows+2;
    used_reads:=used_reads+2;
    captured:=jsonb_build_object(jsonb_build_array(2,'iam.project',p_project_id,'')::text,
        jsonb_build_object('source','{}'::jsonb,'states',
            CASE WHEN mirror_row IS NULL THEN '[]'::jsonb ELSE jsonb_build_array(mirror_row) END));
    -- Без зеркала вложенный селектор не читает каталог и предков проекта.
    IF mirror_row IS NOT NULL THEN
        IF p_rows-used_rows<3 OR used_reads>=p_reads THEN
            RAISE EXCEPTION 'selector move project catalog budget exhausted' USING ERRCODE='54000';
        END IF;
        used_reads:=used_reads+1;
        FOR item IN
            SELECT c.dotted,c.object_type,jsonb_build_array(c.xmin::text,c.ctid::text,to_jsonb(c)) AS image
            FROM ONLY kaname.catalog_resource c WHERE c.live AND c.dotted IN ('iam.account','iam.project') ORDER BY c.dotted COLLATE "C" LIMIT 3
        LOOP
            IF item.object_type='' OR octet_length(item.object_type)>16384
                OR item.object_type ~ '[:#*[:space:][:cntrl:]]'
                OR (item.dotted='iam.project' AND project_model IS NOT NULL)
                OR (item.dotted='iam.account' AND account_model IS NOT NULL) THEN
                RAISE EXCEPTION 'invalid selector move project graph catalog' USING ERRCODE='42501';
            END IF;
            IF item.dotted='iam.project' THEN project_model:=item.object_type;
            ELSE account_model:=item.object_type; END IF;
            used_bytes:=used_bytes+octet_length(item.image::text);
            IF used_bytes>8388608 THEN RAISE EXCEPTION 'selector move project catalog exceeds byte budget' USING ERRCODE='54000'; END IF;
            catalog_rows:=catalog_rows||jsonb_build_array(item.image);
            catalog_resources:=catalog_resources||jsonb_build_array(jsonb_build_object('Module','iam',
                'Resource',substring(item.dotted from 5),'ObjectType',item.object_type));
            used_rows:=used_rows+1;
        END LOOP;
        IF project_model IS NULL OR account_model IS NULL OR project_model=account_model THEN
            RAISE EXCEPTION 'selector move project graph lacks a live catalog type' USING ERRCODE='42501';
        END IF;
        IF used_rows+5>p_rows OR used_reads>=p_reads THEN
            RAISE EXCEPTION 'selector move project edge budget exhausted' USING ERRCODE='54000';
        END IF;
        used_reads:=used_reads+1;
        FOR item IN
            SELECT jsonb_build_array(e.xmin::text,e.ctid::text,to_jsonb(e)) AS image
            FROM ONLY kaname.resource_parent_edge e
            WHERE e.object_type=project_model AND e.object_id=p_project_id ORDER BY e.depth LIMIT 5
        LOOP
            seen_edges:=seen_edges+1;
            IF seen_edges>4 THEN RAISE EXCEPTION 'selector move project edges exceed bound' USING ERRCODE='54000'; END IF;
            used_bytes:=used_bytes+octet_length(item.image::text);
            IF used_bytes>8388608 THEN RAISE EXCEPTION 'selector move project edge exceeds byte budget' USING ERRCODE='54000'; END IF;
            edge_rows:=edge_rows||jsonb_build_array(item.image);
            used_rows:=used_rows+1;
        END LOOP;

        captured:=captured||jsonb_build_object(
            jsonb_build_array(3,project_model,p_project_id,'')::text,jsonb_build_object('source','{}'::jsonb,'states',edge_rows));

        parent_project:=nullif(mirror_row#>>'{2,parent_project_id}','');
        IF parent_project IS NOT NULL THEN
            IF used_rows>=p_rows OR p_reads-used_reads<2 THEN
                RAISE EXCEPTION 'selector move fallback project budget exhausted' USING ERRCODE='54000';
            END IF;
            IF octet_length(parent_project)>16384 OR parent_project ~ '[:#*[:space:][:cntrl:]]' THEN
                RAISE EXCEPTION 'invalid selector move fallback project source' USING ERRCODE='42501';
            END IF;
            -- Общий ключ INSERT/смены PK удерживает в том числе пустое чтение.
            IF NOT pg_try_advisory_xact_lock_shared(1262569303,hashtext(kaname._authority_crud_unique_key_v3(
                'projects',jsonb_build_object('id',parent_project)))) THEN
                RAISE EXCEPTION 'selector move fallback project is changing' USING ERRCODE='40001';
            END IF;
            SELECT jsonb_build_array(p.xmin::text,p.ctid::text,to_jsonb(p)) INTO source_row
            FROM ONLY kaname.projects p WHERE p.id=parent_project FOR SHARE OF p NOWAIT;
            used_reads:=used_reads+2;
            used_bytes:=used_bytes+coalesce(octet_length(source_row::text),0);
            IF used_bytes>8388608 THEN RAISE EXCEPTION 'selector move project source exceeds byte budget' USING ERRCODE='54000'; END IF;
            used_rows:=used_rows+CASE WHEN source_row IS NULL THEN 0 ELSE 1 END;
            captured:=captured||jsonb_build_object(jsonb_build_array(1,'project',parent_project,'')::text,
                jsonb_build_object('source','{}'::jsonb,'states',CASE WHEN source_row IS NULL THEN '[]'::jsonb ELSE jsonb_build_array(source_row) END));
        END IF;
        FOR source_id IN
            SELECT DISTINCT (edge->2->>'parent_id') COLLATE "C"
            FROM jsonb_array_elements(edge_rows) edge
            WHERE edge->2->>'parent_type'=account_model ORDER BY 1
        LOOP
            IF used_rows>=p_rows OR p_reads-used_reads<2 THEN
                RAISE EXCEPTION 'selector move project account budget exhausted' USING ERRCODE='54000';
            END IF;
            IF coalesce(source_id,'')='' OR octet_length(source_id)>16384 OR source_id ~ '[:#*[:space:][:cntrl:]]' THEN
                RAISE EXCEPTION 'invalid selector move project account source' USING ERRCODE='42501';
            END IF;
            IF NOT pg_try_advisory_xact_lock_shared(1262569303,hashtext(kaname._authority_crud_unique_key_v3(
                'accounts',jsonb_build_object('id',source_id)))) THEN
                RAISE EXCEPTION 'selector move account source is changing' USING ERRCODE='40001';
            END IF;
            SELECT jsonb_build_array(a.xmin::text,a.ctid::text,to_jsonb(a)) INTO source_row
            FROM ONLY kaname.accounts a WHERE a.id=source_id FOR SHARE OF a NOWAIT;
            used_reads:=used_reads+2;
            used_bytes:=used_bytes+coalesce(octet_length(source_row::text),0);
            IF used_bytes>8388608 THEN RAISE EXCEPTION 'selector move project source exceeds byte budget' USING ERRCODE='54000'; END IF;
            used_rows:=used_rows+CASE WHEN source_row IS NULL THEN 0 ELSE 1 END;
            captured:=captured||jsonb_build_object(jsonb_build_array(30,'iam.account',source_id,'')::text,
                jsonb_build_object('source','{}'::jsonb,'states',CASE WHEN source_row IS NULL THEN '[]'::jsonb ELSE jsonb_build_array(source_row) END));
        END LOOP;
    END IF;
    project_graph:=kaname._authority_resource_project_graph_v3(captured,
        jsonb_build_object('Live',jsonb_build_object('Resources',catalog_resources)),
        jsonb_build_object('object_type','iam.project','object_id',p_project_id,'present',true,'projection',native_row->2));
    receipt:=jsonb_build_object('nonce',proof->>'nonce','backend_pid',pg_backend_pid(),'txid',pg_current_xact_id()::text,
        'project_id',p_project_id,'native',native_row,'catalog',catalog_rows,'sources',captured,
        'graph',project_graph,'rows',used_rows,'reads',used_reads);
    IF octet_length(receipt::text)>8388608 THEN
        RAISE EXCEPTION 'selector move project graph receipt exceeds byte budget' USING ERRCODE='54000';
    END IF;
    RETURN receipt;
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'selector move project graph is being written' USING ERRCODE='40001';
END;
$hold$;

DO $private$
DECLARE grantee record;fn regprocedure:='kaname._authority_role_move_project_member_graph_hold_v1(text,jsonb,integer,integer)'::regprocedure;
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
DO $member_project_graph$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_role_move_project_copy_graph_hold_v1(text,jsonb,jsonb,integer,integer)','e24a5fc109d80b3f27db2f457bdd6541107b1b6597694adb91d072626f762acf','cf4eda75e663fc9492a87936f67e201d8d7d089919ab2cbe7d96b56481db9d09',$changes$[
  [
    "\nDECLARE\n    proof jsonb;\n    item record;\n    project_model text;\n    account_model text;\n    catalog_rows jsonb:='[]'::jsonb;\n    catalog_resources jsonb:='[]'::jsonb;\n    edge_rows jsonb:='[]'::jsonb;\n    native_row jsonb;\n    mirror_row jsonb;\n    captured jsonb:='{}'::jsonb;\n    project_graph jsonb;\n    receipt jsonb;\n    used_bytes bigint;\n    source_row jsonb;\n    source_id text;\n    parent_project text;\n    used_rows integer:=11;\n    used_reads integer:=4;\n    seen_edges integer:=0;\nBEGIN\n    proof:=kaname._authority_role_move_attestation_v1();\n    IF coalesce(p_project_id,'')='' OR octet_length(p_project_id)>16384\n        OR p_project_id ~ '[:#*[:space:][:cntrl:]]'\n        OR jsonb_typeof(p_native) IS DISTINCT FROM 'array'\n        OR jsonb_typeof(p_mirror) IS DISTINCT FROM 'array'\n        OR jsonb_array_length(p_native)<>3 OR jsonb_array_length(p_mirror)<>3 THEN\n        RAISE EXCEPTION 'invalid selector move project graph coordinates' USING ERRCODE='42501';\n    END IF;\n    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000\n        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096\n        OR octet_length(p_native::text)+octet_length(p_mirror::text)>8388608 THEN\n        RAISE EXCEPTION 'selector move project graph input exceeds budget' USING ERRCODE='54000';\n    END IF;\n    -- Порядок совпадает с существующим удержанием переписи потомков роли.\n    LOCK TABLE ONLY kaname.catalog_resource, ONLY kaname.resource_mirror, ONLY kaname.resource_parent_edge\n        IN SHARE MODE NOWAIT;\n    IF EXISTS(SELECT 1 FROM unnest(ARRAY['kaname.catalog_resource'::regclass,'kaname.resource_mirror'::regclass,\n        'kaname.resource_parent_edge'::regclass,'kaname.projects'::regclass,'kaname.accounts'::regclass]) AS source(oid)\n        WHERE NOT EXISTS(SELECT 1 FROM pg_class c WHERE c.oid=source.oid\n            AND c.relowner=current_user::regrole AND c.relkind='r' AND c.relpersistence='p'\n            AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relispartition OR c.relhasrules)\n            AND NOT EXISTS(SELECT 1 FROM pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid))\n            OR NOT has_table_privilege((proof->>'invoker_oid')::oid,source.oid,'SELECT')) THEN\n        RAISE EXCEPTION 'selector move project graph source custody differs' USING ERRCODE='42501';\n    END IF;\n    IF EXISTS(SELECT 1 FROM (VALUES\n        ('kaname.catalog_resource'::regclass,ARRAY['dotted','live']),\n        ('kaname.resource_mirror'::regclass,ARRAY['object_type','object_id']),\n        ('kaname.resource_parent_edge'::regclass,ARRAY['object_type','object_id','depth']),\n        ('kaname.projects'::regclass,ARRAY['id']),('kaname.accounts'::regclass,ARRAY['id'])\n    ) AS source(rel,cols)\n    WHERE NOT EXISTS(SELECT 1 FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid\n        JOIN pg_am am ON am.oid=idx.relam\n        WHERE i.indrelid=source.rel AND am.amname='btree' AND i.indisready AND i.indisvalid\n            AND i.indisunique AND i.indimmediate AND i.indpred IS NULL AND i.indexprs IS NULL\n            AND (SELECT array_agg(a.attname::text ORDER BY k.pos)\n                FROM unnest(i.indkey::smallint[]) WITH ORDINALITY AS k(attnum,pos)\n                JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum\n                WHERE k.pos<=i.indnkeyatts)=source.cols)) THEN\n        RAISE EXCEPTION 'selector move project graph source keys differ' USING ERRCODE='42501';\n    END IF;\n    IF p_rows-used_rows<5 OR p_reads-used_reads<3 THEN\n        RAISE EXCEPTION 'selector move project graph read budget exhausted' USING ERRCODE='54000';\n    END IF;\n\n    SELECT jsonb_build_array(p.xmin::text,p.ctid::text,to_jsonb(p)) INTO native_row\n    FROM ONLY kaname.projects p WHERE p.id=p_project_id FOR SHARE OF p NOWAIT;\n    SELECT jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) INTO mirror_row\n    FROM ONLY kaname.resource_mirror m WHERE m.object_type='iam.project' AND m.object_id=p_project_id;\n    IF native_row IS NULL OR native_row IS DISTINCT FROM p_native\n        OR mirror_row IS NULL OR mirror_row IS DISTINCT FROM p_mirror THEN\n        RAISE EXCEPTION 'selector move physical project graph changed' USING ERRCODE='40001';\n    END IF;\n    used_bytes:=octet_length(native_row::text)+octet_length(mirror_row::text);\n    used_rows:=used_rows+2;\n    used_reads:=used_reads+3;\n    FOR item IN\n        SELECT c.dotted,c.object_type,jsonb_build_array(c.xmin::text,c.ctid::text,to_jsonb(c)) AS image\n        FROM ONLY kaname.catalog_resource c WHERE c.live AND c.dotted IN ('iam.account','iam.project') ORDER BY c.dotted COLLATE \"C\" LIMIT 3\n    LOOP\n        IF item.object_type='' OR octet_length(item.object_type)>16384\n            OR item.object_type ~ '[:#*[:space:][:cntrl:]]'\n            OR (item.dotted='iam.project' AND project_model IS NOT NULL)\n            OR (item.dotted='iam.account' AND account_model IS NOT NULL) THEN\n            RAISE EXCEPTION 'invalid selector move project graph catalog' USING ERRCODE='42501';\n        END IF;\n        IF item.dotted='iam.project' THEN project_model:=item.object_type;\n        ELSE account_model:=item.object_type; END IF;\n        used_bytes:=used_bytes+octet_length(item.image::text);\n        IF used_bytes>8388608 THEN RAISE EXCEPTION 'selector move project catalog exceeds byte budget' USING ERRCODE='54000'; END IF;\n        catalog_rows:=catalog_rows||jsonb_build_array(item.image);\n        catalog_resources:=catalog_resources||jsonb_build_array(jsonb_build_object('Module','iam',\n            'Resource',substring(item.dotted from 5),'ObjectType',item.object_type));\n        used_rows:=used_rows+1;\n    END LOOP;\n    IF project_model IS NULL OR account_model IS NULL OR project_model=account_model THEN\n        RAISE EXCEPTION 'selector move project graph lacks a live catalog type' USING ERRCODE='42501';\n    END IF;\n    IF used_rows+5>p_rows OR used_reads>=p_reads THEN\n        RAISE EXCEPTION 'selector move project edge budget exhausted' USING ERRCODE='54000';\n    END IF;\n    used_reads:=used_reads+1;\n    FOR item IN\n        SELECT jsonb_build_array(e.xmin::text,e.ctid::text,to_jsonb(e)) AS image\n        FROM ONLY kaname.resource_parent_edge e\n        WHERE e.object_type=project_model AND e.object_id=p_project_id ORDER BY e.depth LIMIT 5\n    LOOP\n        seen_edges:=seen_edges+1;\n        IF seen_edges>4 THEN RAISE EXCEPTION 'selector move project edges exceed bound' USING ERRCODE='54000'; END IF;\n        used_bytes:=used_bytes+octet_length(item.image::text);\n        IF used_bytes>8388608 THEN RAISE EXCEPTION 'selector move project edge exceeds byte budget' USING ERRCODE='54000'; END IF;\n        edge_rows:=edge_rows||jsonb_build_array(item.image);\n        used_rows:=used_rows+1;\n    END LOOP;\n\n    captured:=jsonb_build_object(\n        jsonb_build_array(2,'iam.project',p_project_id,'')::text,jsonb_build_object('source','{}'::jsonb,'states',jsonb_build_array(mirror_row)),\n        jsonb_build_array(3,project_model,p_project_id,'')::text,jsonb_build_object('source','{}'::jsonb,'states',edge_rows));\n\n    parent_project:=nullif(mirror_row#>>'{2,parent_project_id}','');\n    IF parent_project IS NOT NULL THEN\n        IF used_rows>=p_rows OR p_reads-used_reads<2 THEN\n            RAISE EXCEPTION 'selector move fallback project budget exhausted' USING ERRCODE='54000';\n        END IF;\n        IF octet_length(parent_project)>16384 OR parent_project ~ '[:#*[:space:][:cntrl:]]' THEN\n            RAISE EXCEPTION 'invalid selector move fallback project source' USING ERRCODE='42501';\n        END IF;\n        -- Общий ключ INSERT/смены PK удерживает в том числе пустое чтение.\n        IF NOT pg_try_advisory_xact_lock_shared(1262569303,hashtext(kaname._authority_crud_unique_key_v3(\n            'projects',jsonb_build_object('id',parent_project)))) THEN\n            RAISE EXCEPTION 'selector move fallback project is changing' USING ERRCODE='40001';\n        END IF;\n        SELECT jsonb_build_array(p.xmin::text,p.ctid::text,to_jsonb(p)) INTO source_row\n        FROM ONLY kaname.projects p WHERE p.id=parent_project FOR SHARE OF p NOWAIT;\n        used_reads:=used_reads+2;\n        used_bytes:=used_bytes+coalesce(octet_length(source_row::text),0);\n        IF used_bytes>8388608 THEN RAISE EXCEPTION 'selector move project source exceeds byte budget' USING ERRCODE='54000'; END IF;\n        used_rows:=used_rows+CASE WHEN source_row IS NULL THEN 0 ELSE 1 END;\n        captured:=captured||jsonb_build_object(jsonb_build_array(1,'project',parent_project,'')::text,\n            jsonb_build_object('source','{}'::jsonb,'states',CASE WHEN source_row IS NULL THEN '[]'::jsonb ELSE jsonb_build_array(source_row) END));\n    END IF;\n    FOR source_id IN\n        SELECT DISTINCT (edge->2->>'parent_id') COLLATE \"C\"\n        FROM jsonb_array_elements(edge_rows) edge\n        WHERE edge->2->>'parent_type'=account_model ORDER BY 1\n    LOOP\n        IF used_rows>=p_rows OR p_reads-used_reads<2 THEN\n            RAISE EXCEPTION 'selector move project account budget exhausted' USING ERRCODE='54000';\n        END IF;\n        IF coalesce(source_id,'')='' OR octet_length(source_id)>16384 OR source_id ~ '[:#*[:space:][:cntrl:]]' THEN\n            RAISE EXCEPTION 'invalid selector move project account source' USING ERRCODE='42501';\n        END IF;\n        IF NOT pg_try_advisory_xact_lock_shared(1262569303,hashtext(kaname._authority_crud_unique_key_v3(\n            'accounts',jsonb_build_object('id',source_id)))) THEN\n            RAISE EXCEPTION 'selector move account source is changing' USING ERRCODE='40001';\n        END IF;\n        SELECT jsonb_build_array(a.xmin::text,a.ctid::text,to_jsonb(a)) INTO source_row\n        FROM ONLY kaname.accounts a WHERE a.id=source_id FOR SHARE OF a NOWAIT;\n        used_reads:=used_reads+2;\n        used_bytes:=used_bytes+coalesce(octet_length(source_row::text),0);\n        IF used_bytes>8388608 THEN RAISE EXCEPTION 'selector move project source exceeds byte budget' USING ERRCODE='54000'; END IF;\n        used_rows:=used_rows+CASE WHEN source_row IS NULL THEN 0 ELSE 1 END;\n        captured:=captured||jsonb_build_object(jsonb_build_array(30,'iam.account',source_id,'')::text,\n            jsonb_build_object('source','{}'::jsonb,'states',CASE WHEN source_row IS NULL THEN '[]'::jsonb ELSE jsonb_build_array(source_row) END));\n    END LOOP;\n    project_graph:=kaname._authority_resource_project_graph_v3(captured,\n        jsonb_build_object('Live',jsonb_build_object('Resources',catalog_resources)),\n        jsonb_build_object('object_type','iam.project','object_id',p_project_id,'present',true,'projection',native_row->2));\n    receipt:=jsonb_build_object('nonce',proof->>'nonce','backend_pid',pg_backend_pid(),'txid',pg_current_xact_id()::text,\n        'project_id',p_project_id,'native',native_row,'catalog',catalog_rows,'sources',captured,\n        'graph',project_graph,'rows',used_rows,'reads',used_reads);\n    IF octet_length(receipt::text)>8388608 THEN\n        RAISE EXCEPTION 'selector move project graph receipt exceeds byte budget' USING ERRCODE='54000';\n    END IF;\n    RETURN receipt;\nEXCEPTION WHEN lock_not_available THEN\n    RAISE EXCEPTION 'selector move project graph is being written' USING ERRCODE='40001';\nEND;\n",
    "\nDECLARE\n    receipt jsonb;\n    mirror_key text:=jsonb_build_array(2,'iam.project',p_project_id,'')::text;\nBEGIN\n    IF jsonb_typeof(p_mirror) IS DISTINCT FROM 'array' OR jsonb_array_length(p_mirror)<>3 THEN\n        RAISE EXCEPTION 'invalid selector move project graph coordinates' USING ERRCODE='42501';\n    END IF;\n    IF octet_length(p_native::text)+octet_length(p_mirror::text)>8388608 THEN\n        RAISE EXCEPTION 'selector move project graph input exceeds budget' USING ERRCODE='54000';\n    END IF;\n    receipt:=kaname._authority_role_move_project_member_graph_hold_v1(p_project_id,p_native,p_rows,p_reads);\n    IF receipt->'sources'->mirror_key->'states' IS DISTINCT FROM jsonb_build_array(p_mirror) THEN\n        RAISE EXCEPTION 'selector move physical project graph changed' USING ERRCODE='40001';\n    END IF;\n    RETURN receipt;\nEND;\n"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','a0a44d52691dfd2a9dc11e2d9470ea6f0f60d07bf6a5b33b5c2572a75f2d65cf','05ed6299ac64df139dad7ff2e49c479c8f0afc15e1942e7e05777cb8f9e1cc79',$changes$[
  [
    "e24a5fc109d80b3f27db2f457bdd6541107b1b6597694adb91d072626f762acf",
    "cf4eda75e663fc9492a87936f67e201d8d7d089919ab2cbe7d96b56481db9d09"
  ],
  [
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n",
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n ('_authority_role_move_project_member_graph_hold_v1(text,jsonb,integer,integer)','77f20e699d6465dd9a6ac1ec7274e5236099b91b38dcf1b9f604434c2ea7021b',false,'v',true,'private'),\n"
  ],
  [
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n",
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n  ('_authority_role_move_project_member_graph_hold_v1(text,jsonb,integer,integer)','jsonb',4,ARRAY['p_project_id','p_native','p_rows','p_reads']),\n"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','ec0f4597ada3c6b79e9cc4855a8296b50a7179c882ca754634c248001c213e51','473dd6e73e8f921ea5117969ea2b020c006b765055d64294a514193180b41e17',$changes$[
  [
    "a0a44d52691dfd2a9dc11e2d9470ea6f0f60d07bf6a5b33b5c2572a75f2d65cf",
    "05ed6299ac64df139dad7ff2e49c479c8f0afc15e1942e7e05777cb8f9e1cc79"
  ]
]$changes$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','9bd4dca7d23a94b5523251cc79c4dadc2163cd32d18d689902c996918b794a0b','52e6bffe80c124594a5b5198f10466ec9e224fc7bfaf78744f6ed47ae8c2c049',$changes$[
  [
    "a0a44d52691dfd2a9dc11e2d9470ea6f0f60d07bf6a5b33b5c2572a75f2d65cf",
    "05ed6299ac64df139dad7ff2e49c479c8f0afc15e1942e7e05777cb8f9e1cc79"
  ],
  [
    "ec0f4597ada3c6b79e9cc4855a8296b50a7179c882ca754634c248001c213e51",
    "473dd6e73e8f921ea5117969ea2b020c006b765055d64294a514193180b41e17"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'selector move project graph predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'selector move project graph replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move project graph body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move project graph installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selector move project graph storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$member_project_graph$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $member_project_graph$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('authority_metadata_service_account_access_label_ready_v1()','52e6bffe80c124594a5b5198f10466ec9e224fc7bfaf78744f6ed47ae8c2c049','9bd4dca7d23a94b5523251cc79c4dadc2163cd32d18d689902c996918b794a0b',$changes$[
  [
    "473dd6e73e8f921ea5117969ea2b020c006b765055d64294a514193180b41e17",
    "ec0f4597ada3c6b79e9cc4855a8296b50a7179c882ca754634c248001c213e51"
  ],
  [
    "05ed6299ac64df139dad7ff2e49c479c8f0afc15e1942e7e05777cb8f9e1cc79",
    "a0a44d52691dfd2a9dc11e2d9470ea6f0f60d07bf6a5b33b5c2572a75f2d65cf"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','473dd6e73e8f921ea5117969ea2b020c006b765055d64294a514193180b41e17','ec0f4597ada3c6b79e9cc4855a8296b50a7179c882ca754634c248001c213e51',$changes$[
  [
    "05ed6299ac64df139dad7ff2e49c479c8f0afc15e1942e7e05777cb8f9e1cc79",
    "a0a44d52691dfd2a9dc11e2d9470ea6f0f60d07bf6a5b33b5c2572a75f2d65cf"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','05ed6299ac64df139dad7ff2e49c479c8f0afc15e1942e7e05777cb8f9e1cc79','a0a44d52691dfd2a9dc11e2d9470ea6f0f60d07bf6a5b33b5c2572a75f2d65cf',$changes$[
  [
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n  ('_authority_role_move_project_member_graph_hold_v1(text,jsonb,integer,integer)','jsonb',4,ARRAY['p_project_id','p_native','p_rows','p_reads']),\n",
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n"
  ],
  [
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n ('_authority_role_move_project_member_graph_hold_v1(text,jsonb,integer,integer)','77f20e699d6465dd9a6ac1ec7274e5236099b91b38dcf1b9f604434c2ea7021b',false,'v',true,'private'),\n",
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n"
  ],
  [
    "cf4eda75e663fc9492a87936f67e201d8d7d089919ab2cbe7d96b56481db9d09",
    "e24a5fc109d80b3f27db2f457bdd6541107b1b6597694adb91d072626f762acf"
  ]
]$changes$::jsonb),
        ('_authority_role_move_project_copy_graph_hold_v1(text,jsonb,jsonb,integer,integer)','cf4eda75e663fc9492a87936f67e201d8d7d089919ab2cbe7d96b56481db9d09','e24a5fc109d80b3f27db2f457bdd6541107b1b6597694adb91d072626f762acf',$changes$[
  [
    "\nDECLARE\n    receipt jsonb;\n    mirror_key text:=jsonb_build_array(2,'iam.project',p_project_id,'')::text;\nBEGIN\n    IF jsonb_typeof(p_mirror) IS DISTINCT FROM 'array' OR jsonb_array_length(p_mirror)<>3 THEN\n        RAISE EXCEPTION 'invalid selector move project graph coordinates' USING ERRCODE='42501';\n    END IF;\n    IF octet_length(p_native::text)+octet_length(p_mirror::text)>8388608 THEN\n        RAISE EXCEPTION 'selector move project graph input exceeds budget' USING ERRCODE='54000';\n    END IF;\n    receipt:=kaname._authority_role_move_project_member_graph_hold_v1(p_project_id,p_native,p_rows,p_reads);\n    IF receipt->'sources'->mirror_key->'states' IS DISTINCT FROM jsonb_build_array(p_mirror) THEN\n        RAISE EXCEPTION 'selector move physical project graph changed' USING ERRCODE='40001';\n    END IF;\n    RETURN receipt;\nEND;\n",
    "\nDECLARE\n    proof jsonb;\n    item record;\n    project_model text;\n    account_model text;\n    catalog_rows jsonb:='[]'::jsonb;\n    catalog_resources jsonb:='[]'::jsonb;\n    edge_rows jsonb:='[]'::jsonb;\n    native_row jsonb;\n    mirror_row jsonb;\n    captured jsonb:='{}'::jsonb;\n    project_graph jsonb;\n    receipt jsonb;\n    used_bytes bigint;\n    source_row jsonb;\n    source_id text;\n    parent_project text;\n    used_rows integer:=11;\n    used_reads integer:=4;\n    seen_edges integer:=0;\nBEGIN\n    proof:=kaname._authority_role_move_attestation_v1();\n    IF coalesce(p_project_id,'')='' OR octet_length(p_project_id)>16384\n        OR p_project_id ~ '[:#*[:space:][:cntrl:]]'\n        OR jsonb_typeof(p_native) IS DISTINCT FROM 'array'\n        OR jsonb_typeof(p_mirror) IS DISTINCT FROM 'array'\n        OR jsonb_array_length(p_native)<>3 OR jsonb_array_length(p_mirror)<>3 THEN\n        RAISE EXCEPTION 'invalid selector move project graph coordinates' USING ERRCODE='42501';\n    END IF;\n    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000\n        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096\n        OR octet_length(p_native::text)+octet_length(p_mirror::text)>8388608 THEN\n        RAISE EXCEPTION 'selector move project graph input exceeds budget' USING ERRCODE='54000';\n    END IF;\n    -- Порядок совпадает с существующим удержанием переписи потомков роли.\n    LOCK TABLE ONLY kaname.catalog_resource, ONLY kaname.resource_mirror, ONLY kaname.resource_parent_edge\n        IN SHARE MODE NOWAIT;\n    IF EXISTS(SELECT 1 FROM unnest(ARRAY['kaname.catalog_resource'::regclass,'kaname.resource_mirror'::regclass,\n        'kaname.resource_parent_edge'::regclass,'kaname.projects'::regclass,'kaname.accounts'::regclass]) AS source(oid)\n        WHERE NOT EXISTS(SELECT 1 FROM pg_class c WHERE c.oid=source.oid\n            AND c.relowner=current_user::regrole AND c.relkind='r' AND c.relpersistence='p'\n            AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relispartition OR c.relhasrules)\n            AND NOT EXISTS(SELECT 1 FROM pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid))\n            OR NOT has_table_privilege((proof->>'invoker_oid')::oid,source.oid,'SELECT')) THEN\n        RAISE EXCEPTION 'selector move project graph source custody differs' USING ERRCODE='42501';\n    END IF;\n    IF EXISTS(SELECT 1 FROM (VALUES\n        ('kaname.catalog_resource'::regclass,ARRAY['dotted','live']),\n        ('kaname.resource_mirror'::regclass,ARRAY['object_type','object_id']),\n        ('kaname.resource_parent_edge'::regclass,ARRAY['object_type','object_id','depth']),\n        ('kaname.projects'::regclass,ARRAY['id']),('kaname.accounts'::regclass,ARRAY['id'])\n    ) AS source(rel,cols)\n    WHERE NOT EXISTS(SELECT 1 FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid\n        JOIN pg_am am ON am.oid=idx.relam\n        WHERE i.indrelid=source.rel AND am.amname='btree' AND i.indisready AND i.indisvalid\n            AND i.indisunique AND i.indimmediate AND i.indpred IS NULL AND i.indexprs IS NULL\n            AND (SELECT array_agg(a.attname::text ORDER BY k.pos)\n                FROM unnest(i.indkey::smallint[]) WITH ORDINALITY AS k(attnum,pos)\n                JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum\n                WHERE k.pos<=i.indnkeyatts)=source.cols)) THEN\n        RAISE EXCEPTION 'selector move project graph source keys differ' USING ERRCODE='42501';\n    END IF;\n    IF p_rows-used_rows<5 OR p_reads-used_reads<3 THEN\n        RAISE EXCEPTION 'selector move project graph read budget exhausted' USING ERRCODE='54000';\n    END IF;\n\n    SELECT jsonb_build_array(p.xmin::text,p.ctid::text,to_jsonb(p)) INTO native_row\n    FROM ONLY kaname.projects p WHERE p.id=p_project_id FOR SHARE OF p NOWAIT;\n    SELECT jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) INTO mirror_row\n    FROM ONLY kaname.resource_mirror m WHERE m.object_type='iam.project' AND m.object_id=p_project_id;\n    IF native_row IS NULL OR native_row IS DISTINCT FROM p_native\n        OR mirror_row IS NULL OR mirror_row IS DISTINCT FROM p_mirror THEN\n        RAISE EXCEPTION 'selector move physical project graph changed' USING ERRCODE='40001';\n    END IF;\n    used_bytes:=octet_length(native_row::text)+octet_length(mirror_row::text);\n    used_rows:=used_rows+2;\n    used_reads:=used_reads+3;\n    FOR item IN\n        SELECT c.dotted,c.object_type,jsonb_build_array(c.xmin::text,c.ctid::text,to_jsonb(c)) AS image\n        FROM ONLY kaname.catalog_resource c WHERE c.live AND c.dotted IN ('iam.account','iam.project') ORDER BY c.dotted COLLATE \"C\" LIMIT 3\n    LOOP\n        IF item.object_type='' OR octet_length(item.object_type)>16384\n            OR item.object_type ~ '[:#*[:space:][:cntrl:]]'\n            OR (item.dotted='iam.project' AND project_model IS NOT NULL)\n            OR (item.dotted='iam.account' AND account_model IS NOT NULL) THEN\n            RAISE EXCEPTION 'invalid selector move project graph catalog' USING ERRCODE='42501';\n        END IF;\n        IF item.dotted='iam.project' THEN project_model:=item.object_type;\n        ELSE account_model:=item.object_type; END IF;\n        used_bytes:=used_bytes+octet_length(item.image::text);\n        IF used_bytes>8388608 THEN RAISE EXCEPTION 'selector move project catalog exceeds byte budget' USING ERRCODE='54000'; END IF;\n        catalog_rows:=catalog_rows||jsonb_build_array(item.image);\n        catalog_resources:=catalog_resources||jsonb_build_array(jsonb_build_object('Module','iam',\n            'Resource',substring(item.dotted from 5),'ObjectType',item.object_type));\n        used_rows:=used_rows+1;\n    END LOOP;\n    IF project_model IS NULL OR account_model IS NULL OR project_model=account_model THEN\n        RAISE EXCEPTION 'selector move project graph lacks a live catalog type' USING ERRCODE='42501';\n    END IF;\n    IF used_rows+5>p_rows OR used_reads>=p_reads THEN\n        RAISE EXCEPTION 'selector move project edge budget exhausted' USING ERRCODE='54000';\n    END IF;\n    used_reads:=used_reads+1;\n    FOR item IN\n        SELECT jsonb_build_array(e.xmin::text,e.ctid::text,to_jsonb(e)) AS image\n        FROM ONLY kaname.resource_parent_edge e\n        WHERE e.object_type=project_model AND e.object_id=p_project_id ORDER BY e.depth LIMIT 5\n    LOOP\n        seen_edges:=seen_edges+1;\n        IF seen_edges>4 THEN RAISE EXCEPTION 'selector move project edges exceed bound' USING ERRCODE='54000'; END IF;\n        used_bytes:=used_bytes+octet_length(item.image::text);\n        IF used_bytes>8388608 THEN RAISE EXCEPTION 'selector move project edge exceeds byte budget' USING ERRCODE='54000'; END IF;\n        edge_rows:=edge_rows||jsonb_build_array(item.image);\n        used_rows:=used_rows+1;\n    END LOOP;\n\n    captured:=jsonb_build_object(\n        jsonb_build_array(2,'iam.project',p_project_id,'')::text,jsonb_build_object('source','{}'::jsonb,'states',jsonb_build_array(mirror_row)),\n        jsonb_build_array(3,project_model,p_project_id,'')::text,jsonb_build_object('source','{}'::jsonb,'states',edge_rows));\n\n    parent_project:=nullif(mirror_row#>>'{2,parent_project_id}','');\n    IF parent_project IS NOT NULL THEN\n        IF used_rows>=p_rows OR p_reads-used_reads<2 THEN\n            RAISE EXCEPTION 'selector move fallback project budget exhausted' USING ERRCODE='54000';\n        END IF;\n        IF octet_length(parent_project)>16384 OR parent_project ~ '[:#*[:space:][:cntrl:]]' THEN\n            RAISE EXCEPTION 'invalid selector move fallback project source' USING ERRCODE='42501';\n        END IF;\n        -- Общий ключ INSERT/смены PK удерживает в том числе пустое чтение.\n        IF NOT pg_try_advisory_xact_lock_shared(1262569303,hashtext(kaname._authority_crud_unique_key_v3(\n            'projects',jsonb_build_object('id',parent_project)))) THEN\n            RAISE EXCEPTION 'selector move fallback project is changing' USING ERRCODE='40001';\n        END IF;\n        SELECT jsonb_build_array(p.xmin::text,p.ctid::text,to_jsonb(p)) INTO source_row\n        FROM ONLY kaname.projects p WHERE p.id=parent_project FOR SHARE OF p NOWAIT;\n        used_reads:=used_reads+2;\n        used_bytes:=used_bytes+coalesce(octet_length(source_row::text),0);\n        IF used_bytes>8388608 THEN RAISE EXCEPTION 'selector move project source exceeds byte budget' USING ERRCODE='54000'; END IF;\n        used_rows:=used_rows+CASE WHEN source_row IS NULL THEN 0 ELSE 1 END;\n        captured:=captured||jsonb_build_object(jsonb_build_array(1,'project',parent_project,'')::text,\n            jsonb_build_object('source','{}'::jsonb,'states',CASE WHEN source_row IS NULL THEN '[]'::jsonb ELSE jsonb_build_array(source_row) END));\n    END IF;\n    FOR source_id IN\n        SELECT DISTINCT (edge->2->>'parent_id') COLLATE \"C\"\n        FROM jsonb_array_elements(edge_rows) edge\n        WHERE edge->2->>'parent_type'=account_model ORDER BY 1\n    LOOP\n        IF used_rows>=p_rows OR p_reads-used_reads<2 THEN\n            RAISE EXCEPTION 'selector move project account budget exhausted' USING ERRCODE='54000';\n        END IF;\n        IF coalesce(source_id,'')='' OR octet_length(source_id)>16384 OR source_id ~ '[:#*[:space:][:cntrl:]]' THEN\n            RAISE EXCEPTION 'invalid selector move project account source' USING ERRCODE='42501';\n        END IF;\n        IF NOT pg_try_advisory_xact_lock_shared(1262569303,hashtext(kaname._authority_crud_unique_key_v3(\n            'accounts',jsonb_build_object('id',source_id)))) THEN\n            RAISE EXCEPTION 'selector move account source is changing' USING ERRCODE='40001';\n        END IF;\n        SELECT jsonb_build_array(a.xmin::text,a.ctid::text,to_jsonb(a)) INTO source_row\n        FROM ONLY kaname.accounts a WHERE a.id=source_id FOR SHARE OF a NOWAIT;\n        used_reads:=used_reads+2;\n        used_bytes:=used_bytes+coalesce(octet_length(source_row::text),0);\n        IF used_bytes>8388608 THEN RAISE EXCEPTION 'selector move project source exceeds byte budget' USING ERRCODE='54000'; END IF;\n        used_rows:=used_rows+CASE WHEN source_row IS NULL THEN 0 ELSE 1 END;\n        captured:=captured||jsonb_build_object(jsonb_build_array(30,'iam.account',source_id,'')::text,\n            jsonb_build_object('source','{}'::jsonb,'states',CASE WHEN source_row IS NULL THEN '[]'::jsonb ELSE jsonb_build_array(source_row) END));\n    END LOOP;\n    project_graph:=kaname._authority_resource_project_graph_v3(captured,\n        jsonb_build_object('Live',jsonb_build_object('Resources',catalog_resources)),\n        jsonb_build_object('object_type','iam.project','object_id',p_project_id,'present',true,'projection',native_row->2));\n    receipt:=jsonb_build_object('nonce',proof->>'nonce','backend_pid',pg_backend_pid(),'txid',pg_current_xact_id()::text,\n        'project_id',p_project_id,'native',native_row,'catalog',catalog_rows,'sources',captured,\n        'graph',project_graph,'rows',used_rows,'reads',used_reads);\n    IF octet_length(receipt::text)>8388608 THEN\n        RAISE EXCEPTION 'selector move project graph receipt exceeds byte budget' USING ERRCODE='54000';\n    END IF;\n    RETURN receipt;\nEXCEPTION WHEN lock_not_available THEN\n    RAISE EXCEPTION 'selector move project graph is being written' USING ERRCODE='40001';\nEND;\n"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'selector move project graph predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'selector move project graph replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move project graph body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move project graph installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selector move project graph storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$member_project_graph$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_role_move_project_member_graph_hold_v1(text,jsonb,integer,integer);
