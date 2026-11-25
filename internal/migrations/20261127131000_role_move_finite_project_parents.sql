-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_member_project_parent_edges_v1(
    p_parent_type text,p_scope_id text,p_expected jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $reverse$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    forbidden constant text:=U&'[:#*\0001-\0020\007F-\00A0\1680\2000-\200A\2028\2029\202F\205F\3000]';
    source jsonb;
    catalog_versions jsonb;
    parent_model text;
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
    IF coalesce(p_parent_type,'')='' OR octet_length(p_parent_type)>16384 OR p_parent_type COLLATE "C" ~ forbidden THEN
        RAISE EXCEPTION 'invalid reverse project parent type' USING ERRCODE='42501';
    END IF;
    IF coalesce(p_scope_id,'')='' OR octet_length(p_scope_id)>16384 OR p_scope_id COLLATE "C" ~ forbidden THEN
        RAISE EXCEPTION 'invalid reverse project parent identity' USING ERRCODE='42501';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows+3 AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads+1 AND 4096
        OR octet_length(p_expected::text)>8388608 THEN
        RAISE EXCEPTION 'reverse project census exceeds input budget' USING ERRCODE='54000';
    END IF;
    source:=jsonb_build_object('state','held','scope_id',p_scope_id,'nonce',proof->'nonce',
        'invoker_oid',proof->'invoker_oid','catalog_id',proof->'catalog_id',
        'backend_pid',pg_backend_pid(),'txid',pg_current_xact_id()::text);
    source:=source||jsonb_build_object('parent_type',p_parent_type);
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
        IF expected_count>4096 OR jsonb_array_length(p_expected->'catalog')>(CASE WHEN p_parent_type='iam.project' THEN 1 ELSE 2 END) THEN
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
        max(c.model) FILTER(WHERE c.dotted=p_parent_type),max(c.model) FILTER(WHERE c.dotted='iam.project'),
        bool_or(c.too_long)
      INTO catalog_versions,parent_model,project_model,oversized
      FROM (SELECT c.dotted,CASE WHEN octet_length(c.object_type)<=16384 THEN c.object_type END AS model,
                octet_length(c.object_type)>16384 AS too_long,c.xmin::text x,c.ctid::text t
            FROM ONLY kaname.catalog_resource c WHERE c.live AND c.dotted IN (p_parent_type,'iam.project') LIMIT 3) c;
    used_rows:=used_rows+jsonb_array_length(catalog_versions);
    IF oversized THEN RAISE EXCEPTION 'reverse project catalog exceeds byte limit' USING ERRCODE='54000';END IF;
    IF p_expected IS NOT NULL AND catalog_versions IS DISTINCT FROM p_expected->'catalog' THEN
        RAISE EXCEPTION 'reverse project census catalog changed' USING ERRCODE='40001';
    END IF;
    IF jsonb_array_length(catalog_versions)>(CASE WHEN p_parent_type='iam.project' THEN 1 ELSE 2 END) OR parent_model='' OR project_model=''
        OR (parent_model=project_model AND p_parent_type<>'iam.project') OR parent_model COLLATE "C" ~ forbidden OR project_model COLLATE "C" ~ forbidden THEN
        RAISE EXCEPTION 'ambiguous or invalid reverse project catalog' USING ERRCODE='42501';
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
        WHERE project_model IS NOT NULL AND e.parent_type=parent_model AND e.parent_id=p_scope_id LIMIT cap+1;
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
    RETURN result||jsonb_build_object('bytes',image_bytes);
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'reverse project census sources busy' USING ERRCODE='40001';
END;
$reverse$;

DO $private$
DECLARE grantee record;fn regprocedure:='kaname._authority_role_move_member_project_parent_edges_v1(text,text,jsonb,integer,integer)'::regprocedure;
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
        ('_authority_role_move_member_projects_v1(jsonb,jsonb,jsonb,integer,integer)','5eccdddd9492815a4ee47c0a3f2e3110cec234d7cef7606cddbee3fef2a40f15','e1f118fe1f1be00d7d662acb352c6599e94e51b7ca14b569bbf25fccb93d78e2',$changes$[
  [
    "    nested_types jsonb;",
    "    nested_types jsonb;\n    finite_parents jsonb;\n    parent_ref jsonb;\n    reverse_receipt jsonb;\n    parent_receipts jsonb:='{}'::jsonb;\n    parent_key text;\n    reverse_ids jsonb:='{}'::jsonb;\n    finite_children text[]:=ARRAY[]::text[];"
  ],
  [
    "    IF jsonb_typeof(p_plan->'items')",
    "    IF jsonb_typeof(p_census->'moved_role_id') IS DISTINCT FROM 'string' OR coalesce(p_census->>'moved_role_id','')=''\n        OR jsonb_typeof(p_census->'bindings') IS DISTINCT FROM 'array'\n        OR jsonb_typeof(p_plan->'items')"
  ],
  [
    "            OR jsonb_typeof(p_expected->'nested_types')",
    "            OR jsonb_typeof(p_expected->'finite_parents') IS DISTINCT FROM 'array'\n            OR jsonb_typeof(p_expected->'parent_edges') IS DISTINCT FROM 'object'\n            OR jsonb_typeof(p_expected->'nested_types')"
  ],
  [
    "+jsonb_array_length(p_census->'members')+",
    "+jsonb_array_length(p_census->'bindings')+jsonb_array_length(p_census->'members')+"
  ],
  [
    "    SELECT coalesce(bool_or(i->>'child_type'='iam.project'\n            OR (i->>'read_type'='iam.project' AND i->>'guard' IS DISTINCT FROM 'objects')),false),\n        coalesce(sum(CASE WHEN i->>'read_type'='iam.project' AND i->>'guard'='objects'\n            THEN jsonb_array_length(i->'object_ids') ELSE 0 END),0)\n        INTO all_native,n FROM jsonb_array_elements(p_plan->'items') i;\n    IF n>p_rows-used_rows THEN RAISE EXCEPTION 'finite project positions exceed budget' USING ERRCODE='54000';END IF;\n    used_rows:=used_rows+n::integer;\n    SELECT coalesce(jsonb_object_agg(h->>'binding_id',true),'{}'::jsonb) INTO holders FROM jsonb_array_elements(p_plan->'holders') h;\n",
    "    SELECT coalesce(sum(CASE WHEN i->>'guard'='objects' AND (i->>'read_type'='iam.project' OR i->>'child_type'='iam.project')\n            THEN jsonb_array_length(i->'object_ids') ELSE 0 END),0)\n        INTO n FROM jsonb_array_elements(p_plan->'items') i;\n    IF n>p_rows-used_rows THEN RAISE EXCEPTION 'finite project positions exceed budget' USING ERRCODE='54000';END IF;\n    used_rows:=used_rows+n::integer;\n    -- Прежние члены и ledger принадлежат физическим привязкам роли независимо\n    -- от срока, отзыва и появления держателя в новом плане.\n    SELECT coalesce(jsonb_object_agg(b#>>'{2,id}',true),'{}'::jsonb) INTO holders\n        FROM jsonb_array_elements(p_census->'bindings') b WHERE b#>>'{2,role_id}'=p_census->>'moved_role_id';\n"
  ],
  [
    "    SELECT coalesce(jsonb_agg(t ORDER BY t COLLATE \"C\"),'[]'::jsonb) INTO nested_types\n        FROM (SELECT DISTINCT (i->>'read_type') COLLATE \"C\" t FROM jsonb_array_elements(p_plan->'items') i\n            WHERE i->>'child_type'='iam.project') types;\n",
    "    -- Область аккаунта содержит единственный родной аккаунт, область проекта\n    -- не содержит аккаунтов. Собственный проект проектной области тоже однозначен.\n    WITH items AS (\n        SELECT i->>'read_type' typ,i->>'guard' guard,i->'object_ids' ids,\n            i#>>'{scope,0}' scope_kind,i#>>'{scope,1}' scope_id\n        FROM jsonb_array_elements(p_plan->'items') i WHERE i->>'child_type'='iam.project'\n    ), parents AS (\n        SELECT typ,scope_id AS id FROM items\n        WHERE ((typ='iam.account' AND scope_kind='account') OR (typ='iam.project' AND scope_kind='project'))\n            AND (guard<>'objects' OR ids ? scope_id)\n        UNION ALL\n        SELECT typ,v.id FROM items CROSS JOIN LATERAL jsonb_array_elements_text(\n            CASE WHEN guard='objects' THEN ids ELSE '[]'::jsonb END) v(id)\n        WHERE NOT (typ='iam.account' AND scope_kind IN ('account','project'))\n            AND NOT (typ='iam.project' AND scope_kind='project')\n    ), distinct_parents AS (SELECT DISTINCT typ COLLATE \"C\" typ,id COLLATE \"C\" id FROM parents)\n    SELECT coalesce(jsonb_agg(jsonb_build_array(typ,id) ORDER BY typ COLLATE \"C\",id COLLATE \"C\"),'[]'::jsonb)\n        INTO finite_parents FROM distinct_parents;\n    SELECT coalesce(jsonb_agg(t ORDER BY t COLLATE \"C\"),'[]'::jsonb) INTO nested_types FROM (\n        SELECT DISTINCT (i->>'read_type') COLLATE \"C\" t FROM jsonb_array_elements(p_plan->'items') i\n        WHERE i->>'child_type'='iam.project' AND i->>'guard'<>'objects'\n            AND NOT (i->>'read_type'='iam.account' AND i#>>'{scope,0}' IN ('account','project'))\n            AND NOT (i->>'read_type'='iam.project' AND i#>>'{scope,0}'='project')\n    ) types;\n    SELECT nested_types<>'[]'::jsonb OR EXISTS(SELECT FROM jsonb_array_elements(p_plan->'items') i\n        WHERE i->>'read_type'='iam.project' AND i->>'guard'<>'objects' AND i#>>'{scope,0}'<>'project')\n        INTO all_native;\n"
  ],
  [
    "IF NOT ((p_expected->'nested_types') @> nested_types)",
    "IF EXISTS(SELECT FROM jsonb_array_elements(finite_parents) r\n                WHERE NOT (p_expected->'parent_edges' ? (r::text)))\n            OR NOT ((p_expected->'nested_types') @> nested_types)"
  ],
  [
    "        nested_types:=p_expected->'nested_types';",
    "        nested_types:=p_expected->'nested_types';\n        finite_parents:=p_expected->'finite_parents';"
  ],
  [
    "IF all_native OR finite_ids<>'[]'::jsonb THEN",
    "IF all_native OR finite_ids<>'[]'::jsonb OR finite_parents<>'[]'::jsonb THEN"
  ],
  [
    "    IF all_native THEN\n",
    "    -- Каждая конечная позиция использует обратный индекс. Отпечаток включает\n    -- чужие типы, повторные рёбра, отсутствие зеркала и пустой ответ.\n    FOR parent_ref IN SELECT value FROM jsonb_array_elements(finite_parents) LOOP\n        parent_key:=parent_ref::text;\n        IF p_expected IS NOT NULL AND jsonb_typeof(p_expected->'parent_edges'->parent_key) IS DISTINCT FROM 'object' THEN\n            RAISE EXCEPTION 'finite parent edge receipt missing' USING ERRCODE='40001';\n        END IF;\n        reverse_receipt:=kaname._authority_role_move_member_project_parent_edges_v1(parent_ref->>0,parent_ref->>1,\n            p_expected->'parent_edges'->parent_key,p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(reverse_receipt->>'rows')::integer;\n        used_reads:=used_reads+(reverse_receipt->>'reads')::integer;\n        IF jsonb_array_length(reverse_receipt->'candidate_ids')>p_rows-used_rows THEN\n            RAISE EXCEPTION 'finite parent project union exceeds budget' USING ERRCODE='54000';\n        END IF;\n        used_rows:=used_rows+jsonb_array_length(reverse_receipt->'candidate_ids');\n        bytes:=bytes+(reverse_receipt->>'bytes')::bigint+octet_length(parent_key)+octet_length(reverse_receipt::text)+4;\n        IF bytes>8388608 THEN RAISE EXCEPTION 'finite parent receipts exceed byte budget' USING ERRCODE='54000';END IF;\n        parent_receipts:=parent_receipts||jsonb_build_object(parent_key,reverse_receipt->'source');\n        FOR project_id IN SELECT value FROM jsonb_array_elements_text(reverse_receipt->'candidate_ids') LOOP\n            IF NOT (reverse_ids ? project_id) THEN\n                reverse_ids:=reverse_ids||jsonb_build_object(project_id,true);\n                finite_children:=array_append(finite_children,project_id);\n            END IF;\n        END LOOP;\n    END LOOP;\n    IF all_native THEN\n"
  ],
  [
    "                used_rows:=used_rows+1;\n                IF native_ids ? mirror_id",
    "                bytes:=bytes+octet_length(mirror_id)+4;\n                IF bytes>8388608 THEN RAISE EXCEPTION 'nested project mirror bytes exceed budget' USING ERRCODE='54000';END IF;\n                used_rows:=used_rows+1;\n                IF native_ids ? mirror_id"
  ],
  [
    "FOR edge IN SELECT e.parent_type FROM ONLY",
    "FOR edge IN SELECT e.parent_type,e.parent_id FROM ONLY"
  ],
  [
    "                    IF parent_models ? edge.parent_type THEN",
    "                    bytes:=bytes+octet_length(edge.parent_type)+octet_length(edge.parent_id)+8;\n                    IF octet_length(edge.parent_type)>16384 OR octet_length(edge.parent_id)>16384 OR bytes>8388608 THEN\n                        RAISE EXCEPTION 'nested project edge bytes exceed budget' USING ERRCODE='54000';\n                    END IF;\n                    IF parent_models ? edge.parent_type THEN"
  ],
  [
    "        UNION SELECT id COLLATE \"C\" FROM jsonb_array_elements_text(finite_ids)",
    "        UNION SELECT id COLLATE \"C\" FROM unnest(finite_children) id\n        UNION SELECT id COLLATE \"C\" FROM jsonb_array_elements_text(finite_ids)"
  ],
  [
    "        held:='null'::jsonb;",
    "        IF native IS NULL AND reverse_ids ? project_id THEN\n            RAISE EXCEPTION 'nested project mirror and edge lack a native project' USING ERRCODE='40001';\n        END IF;\n        held:='null'::jsonb;"
  ],
  [
    "'all_native',all_native,'nested_types'",
    "'all_native',all_native,'finite_parents',finite_parents,'parent_edges',parent_receipts,'nested_types'"
  ],
  [
    "    typ text;",
    "    scanned_parent_type text;"
  ],
  [
    "        FOR typ IN SELECT value FROM jsonb_array_elements_text(nested_types) LOOP",
    "        FOR scanned_parent_type IN SELECT value FROM jsonb_array_elements_text(nested_types) LOOP"
  ],
  [
    "                INTO model,catalog_image FROM ONLY kaname.catalog_resource c WHERE c.dotted=typ AND c.live;",
    "                INTO model,catalog_image FROM ONLY kaname.catalog_resource c WHERE c.dotted=scanned_parent_type AND c.live;"
  ],
  [
    "            bytes:=bytes+coalesce(octet_length(catalog_image::text),4)+octet_length(typ)+4;",
    "            bytes:=bytes+coalesce(octet_length(catalog_image::text),4)+octet_length(scanned_parent_type)+4;"
  ],
  [
    "            catalog_images:=catalog_images||jsonb_build_object(typ,catalog_image);",
    "            catalog_images:=catalog_images||jsonb_build_object(scanned_parent_type,catalog_image);"
  ]
]$changes$::jsonb),
        ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','89aa9d6ed2bc4c6edb63c9c06ff3e8f30aee3efa45e776b1fd1fa3810c1722a2','139d02e18dec6d344339a5b496e0e761e13213f57260a7db5334c8a3b3ed9660',$changes$[
  [
    "frozen->'binding_census',NULL,p_rows-used_rows",
    "(frozen->'binding_census')||jsonb_build_object('moved_role_id',frozen->'role_id'),NULL,p_rows-used_rows"
  ]
]$changes$::jsonb),
        ('_authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)','9af62dcdbd730555e6e297e7ade8cbc0c656f946654258196c6289bb707d1c75','93c7d170086859b993870a838a1270d673f6ae80c98725339b3aa63f0a65a4d9',$changes$[
  [
    "predicates->'plan',p_frozen->'binding_census',p_frozen->'member_projects'",
    "predicates->'plan',(p_frozen->'binding_census')||jsonb_build_object('moved_role_id',root_id),p_frozen->'member_projects'"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','68d117b6176dc3e08f00edd4ea26d1f0503215f81e3f873ceb6bdad75b866df0','8be8f6030fc62b0dddb14e31e6a59e5dc84c7fed58076ae0023aa9819c3f8c10',$changes$[
  [
    "89aa9d6ed2bc4c6edb63c9c06ff3e8f30aee3efa45e776b1fd1fa3810c1722a2",
    "139d02e18dec6d344339a5b496e0e761e13213f57260a7db5334c8a3b3ed9660"
  ],
  [
    "9af62dcdbd730555e6e297e7ade8cbc0c656f946654258196c6289bb707d1c75",
    "93c7d170086859b993870a838a1270d673f6ae80c98725339b3aa63f0a65a4d9"
  ],
  [
    "5eccdddd9492815a4ee47c0a3f2e3110cec234d7cef7606cddbee3fef2a40f15",
    "e1f118fe1f1be00d7d662acb352c6599e94e51b7ca14b569bbf25fccb93d78e2"
  ],
  [
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n",
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n ('_authority_role_move_member_project_parent_edges_v1(text,text,jsonb,integer,integer)','fdeca3e8fd3d816b5cfdc47bdf30f3d9e2c8b083041c46ddfcad84539c87771a',false,'v',true,'private'),\n"
  ],
  [
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n",
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n  ('_authority_role_move_member_project_parent_edges_v1(text,text,jsonb,integer,integer)','jsonb',5,ARRAY['p_parent_type','p_scope_id','p_expected','p_rows','p_reads']),\n"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','3744bc50c9796c33fed950cca61de59ec25979e5ea7aa64be4a19f3adcaf4ec0','00004e4b21a491f8787895c1109aefff0645bafd067857f0a264a302dce147d2',$changes$[
  [
    "68d117b6176dc3e08f00edd4ea26d1f0503215f81e3f873ceb6bdad75b866df0",
    "8be8f6030fc62b0dddb14e31e6a59e5dc84c7fed58076ae0023aa9819c3f8c10"
  ]
]$changes$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','b4a21cc93994221c808eb9f62542e40521c38edd2eadd5262cb8e10339032ec5','366002c5983dd88798848297d9cb19e85b5ae3f5b8c470ecfb22d3ee05dbf3f7',$changes$[
  [
    "68d117b6176dc3e08f00edd4ea26d1f0503215f81e3f873ceb6bdad75b866df0",
    "8be8f6030fc62b0dddb14e31e6a59e5dc84c7fed58076ae0023aa9819c3f8c10"
  ],
  [
    "3744bc50c9796c33fed950cca61de59ec25979e5ea7aa64be4a19f3adcaf4ec0",
    "00004e4b21a491f8787895c1109aefff0645bafd067857f0a264a302dce147d2"
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
        ('authority_metadata_service_account_access_label_ready_v1()','366002c5983dd88798848297d9cb19e85b5ae3f5b8c470ecfb22d3ee05dbf3f7','b4a21cc93994221c808eb9f62542e40521c38edd2eadd5262cb8e10339032ec5',$changes$[
  [
    "00004e4b21a491f8787895c1109aefff0645bafd067857f0a264a302dce147d2",
    "3744bc50c9796c33fed950cca61de59ec25979e5ea7aa64be4a19f3adcaf4ec0"
  ],
  [
    "8be8f6030fc62b0dddb14e31e6a59e5dc84c7fed58076ae0023aa9819c3f8c10",
    "68d117b6176dc3e08f00edd4ea26d1f0503215f81e3f873ceb6bdad75b866df0"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','00004e4b21a491f8787895c1109aefff0645bafd067857f0a264a302dce147d2','3744bc50c9796c33fed950cca61de59ec25979e5ea7aa64be4a19f3adcaf4ec0',$changes$[
  [
    "8be8f6030fc62b0dddb14e31e6a59e5dc84c7fed58076ae0023aa9819c3f8c10",
    "68d117b6176dc3e08f00edd4ea26d1f0503215f81e3f873ceb6bdad75b866df0"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','8be8f6030fc62b0dddb14e31e6a59e5dc84c7fed58076ae0023aa9819c3f8c10','68d117b6176dc3e08f00edd4ea26d1f0503215f81e3f873ceb6bdad75b866df0',$changes$[
  [
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n  ('_authority_role_move_member_project_parent_edges_v1(text,text,jsonb,integer,integer)','jsonb',5,ARRAY['p_parent_type','p_scope_id','p_expected','p_rows','p_reads']),\n",
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n"
  ],
  [
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n ('_authority_role_move_member_project_parent_edges_v1(text,text,jsonb,integer,integer)','fdeca3e8fd3d816b5cfdc47bdf30f3d9e2c8b083041c46ddfcad84539c87771a',false,'v',true,'private'),\n",
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n"
  ],
  [
    "e1f118fe1f1be00d7d662acb352c6599e94e51b7ca14b569bbf25fccb93d78e2",
    "5eccdddd9492815a4ee47c0a3f2e3110cec234d7cef7606cddbee3fef2a40f15"
  ],
  [
    "93c7d170086859b993870a838a1270d673f6ae80c98725339b3aa63f0a65a4d9",
    "9af62dcdbd730555e6e297e7ade8cbc0c656f946654258196c6289bb707d1c75"
  ],
  [
    "139d02e18dec6d344339a5b496e0e761e13213f57260a7db5334c8a3b3ed9660",
    "89aa9d6ed2bc4c6edb63c9c06ff3e8f30aee3efa45e776b1fd1fa3810c1722a2"
  ]
]$changes$::jsonb),
        ('_authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)','93c7d170086859b993870a838a1270d673f6ae80c98725339b3aa63f0a65a4d9','9af62dcdbd730555e6e297e7ade8cbc0c656f946654258196c6289bb707d1c75',$changes$[
  [
    "predicates->'plan',(p_frozen->'binding_census')||jsonb_build_object('moved_role_id',root_id),p_frozen->'member_projects'",
    "predicates->'plan',p_frozen->'binding_census',p_frozen->'member_projects'"
  ]
]$changes$::jsonb),
        ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','139d02e18dec6d344339a5b496e0e761e13213f57260a7db5334c8a3b3ed9660','89aa9d6ed2bc4c6edb63c9c06ff3e8f30aee3efa45e776b1fd1fa3810c1722a2',$changes$[
  [
    "(frozen->'binding_census')||jsonb_build_object('moved_role_id',frozen->'role_id'),NULL,p_rows-used_rows",
    "frozen->'binding_census',NULL,p_rows-used_rows"
  ]
]$changes$::jsonb),
        ('_authority_role_move_member_projects_v1(jsonb,jsonb,jsonb,integer,integer)','e1f118fe1f1be00d7d662acb352c6599e94e51b7ca14b569bbf25fccb93d78e2','5eccdddd9492815a4ee47c0a3f2e3110cec234d7cef7606cddbee3fef2a40f15',$changes$[
  [
    "            catalog_images:=catalog_images||jsonb_build_object(scanned_parent_type,catalog_image);",
    "            catalog_images:=catalog_images||jsonb_build_object(typ,catalog_image);"
  ],
  [
    "            bytes:=bytes+coalesce(octet_length(catalog_image::text),4)+octet_length(scanned_parent_type)+4;",
    "            bytes:=bytes+coalesce(octet_length(catalog_image::text),4)+octet_length(typ)+4;"
  ],
  [
    "                INTO model,catalog_image FROM ONLY kaname.catalog_resource c WHERE c.dotted=scanned_parent_type AND c.live;",
    "                INTO model,catalog_image FROM ONLY kaname.catalog_resource c WHERE c.dotted=typ AND c.live;"
  ],
  [
    "        FOR scanned_parent_type IN SELECT value FROM jsonb_array_elements_text(nested_types) LOOP",
    "        FOR typ IN SELECT value FROM jsonb_array_elements_text(nested_types) LOOP"
  ],
  [
    "    scanned_parent_type text;",
    "    typ text;"
  ],
  [
    "'all_native',all_native,'finite_parents',finite_parents,'parent_edges',parent_receipts,'nested_types'",
    "'all_native',all_native,'nested_types'"
  ],
  [
    "        IF native IS NULL AND reverse_ids ? project_id THEN\n            RAISE EXCEPTION 'nested project mirror and edge lack a native project' USING ERRCODE='40001';\n        END IF;\n        held:='null'::jsonb;",
    "        held:='null'::jsonb;"
  ],
  [
    "        UNION SELECT id COLLATE \"C\" FROM unnest(finite_children) id\n        UNION SELECT id COLLATE \"C\" FROM jsonb_array_elements_text(finite_ids)",
    "        UNION SELECT id COLLATE \"C\" FROM jsonb_array_elements_text(finite_ids)"
  ],
  [
    "                    bytes:=bytes+octet_length(edge.parent_type)+octet_length(edge.parent_id)+8;\n                    IF octet_length(edge.parent_type)>16384 OR octet_length(edge.parent_id)>16384 OR bytes>8388608 THEN\n                        RAISE EXCEPTION 'nested project edge bytes exceed budget' USING ERRCODE='54000';\n                    END IF;\n                    IF parent_models ? edge.parent_type THEN",
    "                    IF parent_models ? edge.parent_type THEN"
  ],
  [
    "FOR edge IN SELECT e.parent_type,e.parent_id FROM ONLY",
    "FOR edge IN SELECT e.parent_type FROM ONLY"
  ],
  [
    "                bytes:=bytes+octet_length(mirror_id)+4;\n                IF bytes>8388608 THEN RAISE EXCEPTION 'nested project mirror bytes exceed budget' USING ERRCODE='54000';END IF;\n                used_rows:=used_rows+1;\n                IF native_ids ? mirror_id",
    "                used_rows:=used_rows+1;\n                IF native_ids ? mirror_id"
  ],
  [
    "    -- Каждая конечная позиция использует обратный индекс. Отпечаток включает\n    -- чужие типы, повторные рёбра, отсутствие зеркала и пустой ответ.\n    FOR parent_ref IN SELECT value FROM jsonb_array_elements(finite_parents) LOOP\n        parent_key:=parent_ref::text;\n        IF p_expected IS NOT NULL AND jsonb_typeof(p_expected->'parent_edges'->parent_key) IS DISTINCT FROM 'object' THEN\n            RAISE EXCEPTION 'finite parent edge receipt missing' USING ERRCODE='40001';\n        END IF;\n        reverse_receipt:=kaname._authority_role_move_member_project_parent_edges_v1(parent_ref->>0,parent_ref->>1,\n            p_expected->'parent_edges'->parent_key,p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(reverse_receipt->>'rows')::integer;\n        used_reads:=used_reads+(reverse_receipt->>'reads')::integer;\n        IF jsonb_array_length(reverse_receipt->'candidate_ids')>p_rows-used_rows THEN\n            RAISE EXCEPTION 'finite parent project union exceeds budget' USING ERRCODE='54000';\n        END IF;\n        used_rows:=used_rows+jsonb_array_length(reverse_receipt->'candidate_ids');\n        bytes:=bytes+(reverse_receipt->>'bytes')::bigint+octet_length(parent_key)+octet_length(reverse_receipt::text)+4;\n        IF bytes>8388608 THEN RAISE EXCEPTION 'finite parent receipts exceed byte budget' USING ERRCODE='54000';END IF;\n        parent_receipts:=parent_receipts||jsonb_build_object(parent_key,reverse_receipt->'source');\n        FOR project_id IN SELECT value FROM jsonb_array_elements_text(reverse_receipt->'candidate_ids') LOOP\n            IF NOT (reverse_ids ? project_id) THEN\n                reverse_ids:=reverse_ids||jsonb_build_object(project_id,true);\n                finite_children:=array_append(finite_children,project_id);\n            END IF;\n        END LOOP;\n    END LOOP;\n    IF all_native THEN\n",
    "    IF all_native THEN\n"
  ],
  [
    "IF all_native OR finite_ids<>'[]'::jsonb OR finite_parents<>'[]'::jsonb THEN",
    "IF all_native OR finite_ids<>'[]'::jsonb THEN"
  ],
  [
    "        nested_types:=p_expected->'nested_types';\n        finite_parents:=p_expected->'finite_parents';",
    "        nested_types:=p_expected->'nested_types';"
  ],
  [
    "IF EXISTS(SELECT FROM jsonb_array_elements(finite_parents) r\n                WHERE NOT (p_expected->'parent_edges' ? (r::text)))\n            OR NOT ((p_expected->'nested_types') @> nested_types)",
    "IF NOT ((p_expected->'nested_types') @> nested_types)"
  ],
  [
    "    -- Область аккаунта содержит единственный родной аккаунт, область проекта\n    -- не содержит аккаунтов. Собственный проект проектной области тоже однозначен.\n    WITH items AS (\n        SELECT i->>'read_type' typ,i->>'guard' guard,i->'object_ids' ids,\n            i#>>'{scope,0}' scope_kind,i#>>'{scope,1}' scope_id\n        FROM jsonb_array_elements(p_plan->'items') i WHERE i->>'child_type'='iam.project'\n    ), parents AS (\n        SELECT typ,scope_id AS id FROM items\n        WHERE ((typ='iam.account' AND scope_kind='account') OR (typ='iam.project' AND scope_kind='project'))\n            AND (guard<>'objects' OR ids ? scope_id)\n        UNION ALL\n        SELECT typ,v.id FROM items CROSS JOIN LATERAL jsonb_array_elements_text(\n            CASE WHEN guard='objects' THEN ids ELSE '[]'::jsonb END) v(id)\n        WHERE NOT (typ='iam.account' AND scope_kind IN ('account','project'))\n            AND NOT (typ='iam.project' AND scope_kind='project')\n    ), distinct_parents AS (SELECT DISTINCT typ COLLATE \"C\" typ,id COLLATE \"C\" id FROM parents)\n    SELECT coalesce(jsonb_agg(jsonb_build_array(typ,id) ORDER BY typ COLLATE \"C\",id COLLATE \"C\"),'[]'::jsonb)\n        INTO finite_parents FROM distinct_parents;\n    SELECT coalesce(jsonb_agg(t ORDER BY t COLLATE \"C\"),'[]'::jsonb) INTO nested_types FROM (\n        SELECT DISTINCT (i->>'read_type') COLLATE \"C\" t FROM jsonb_array_elements(p_plan->'items') i\n        WHERE i->>'child_type'='iam.project' AND i->>'guard'<>'objects'\n            AND NOT (i->>'read_type'='iam.account' AND i#>>'{scope,0}' IN ('account','project'))\n            AND NOT (i->>'read_type'='iam.project' AND i#>>'{scope,0}'='project')\n    ) types;\n    SELECT nested_types<>'[]'::jsonb OR EXISTS(SELECT FROM jsonb_array_elements(p_plan->'items') i\n        WHERE i->>'read_type'='iam.project' AND i->>'guard'<>'objects' AND i#>>'{scope,0}'<>'project')\n        INTO all_native;\n",
    "    SELECT coalesce(jsonb_agg(t ORDER BY t COLLATE \"C\"),'[]'::jsonb) INTO nested_types\n        FROM (SELECT DISTINCT (i->>'read_type') COLLATE \"C\" t FROM jsonb_array_elements(p_plan->'items') i\n            WHERE i->>'child_type'='iam.project') types;\n"
  ],
  [
    "    SELECT coalesce(sum(CASE WHEN i->>'guard'='objects' AND (i->>'read_type'='iam.project' OR i->>'child_type'='iam.project')\n            THEN jsonb_array_length(i->'object_ids') ELSE 0 END),0)\n        INTO n FROM jsonb_array_elements(p_plan->'items') i;\n    IF n>p_rows-used_rows THEN RAISE EXCEPTION 'finite project positions exceed budget' USING ERRCODE='54000';END IF;\n    used_rows:=used_rows+n::integer;\n    -- Прежние члены и ledger принадлежат физическим привязкам роли независимо\n    -- от срока, отзыва и появления держателя в новом плане.\n    SELECT coalesce(jsonb_object_agg(b#>>'{2,id}',true),'{}'::jsonb) INTO holders\n        FROM jsonb_array_elements(p_census->'bindings') b WHERE b#>>'{2,role_id}'=p_census->>'moved_role_id';\n",
    "    SELECT coalesce(bool_or(i->>'child_type'='iam.project'\n            OR (i->>'read_type'='iam.project' AND i->>'guard' IS DISTINCT FROM 'objects')),false),\n        coalesce(sum(CASE WHEN i->>'read_type'='iam.project' AND i->>'guard'='objects'\n            THEN jsonb_array_length(i->'object_ids') ELSE 0 END),0)\n        INTO all_native,n FROM jsonb_array_elements(p_plan->'items') i;\n    IF n>p_rows-used_rows THEN RAISE EXCEPTION 'finite project positions exceed budget' USING ERRCODE='54000';END IF;\n    used_rows:=used_rows+n::integer;\n    SELECT coalesce(jsonb_object_agg(h->>'binding_id',true),'{}'::jsonb) INTO holders FROM jsonb_array_elements(p_plan->'holders') h;\n"
  ],
  [
    "+jsonb_array_length(p_census->'bindings')+jsonb_array_length(p_census->'members')+",
    "+jsonb_array_length(p_census->'members')+"
  ],
  [
    "            OR jsonb_typeof(p_expected->'finite_parents') IS DISTINCT FROM 'array'\n            OR jsonb_typeof(p_expected->'parent_edges') IS DISTINCT FROM 'object'\n            OR jsonb_typeof(p_expected->'nested_types')",
    "            OR jsonb_typeof(p_expected->'nested_types')"
  ],
  [
    "    IF jsonb_typeof(p_census->'moved_role_id') IS DISTINCT FROM 'string' OR coalesce(p_census->>'moved_role_id','')=''\n        OR jsonb_typeof(p_census->'bindings') IS DISTINCT FROM 'array'\n        OR jsonb_typeof(p_plan->'items')",
    "    IF jsonb_typeof(p_plan->'items')"
  ],
  [
    "    nested_types jsonb;\n    finite_parents jsonb;\n    parent_ref jsonb;\n    reverse_receipt jsonb;\n    parent_receipts jsonb:='{}'::jsonb;\n    parent_key text;\n    reverse_ids jsonb:='{}'::jsonb;\n    finite_children text[]:=ARRAY[]::text[];",
    "    nested_types jsonb;"
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

DROP FUNCTION kaname._authority_role_move_member_project_parent_edges_v1(text,text,jsonb,integer,integer);
