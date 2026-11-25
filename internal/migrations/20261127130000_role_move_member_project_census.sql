-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Обе стороны плана используют одну физическую перепись проектов. Сужение
-- набора держателей по TTL сохраняет весь исходный набор до конца проверки.
CREATE FUNCTION kaname._authority_role_move_member_projects_v1(
    p_plan jsonb,p_census jsonb,p_expected jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $universe$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    all_native boolean;
    nested_types jsonb;
    parent_models jsonb;
    catalog_images jsonb:='{}'::jsonb;
    catalog_image jsonb;
    project_model text;
    native_ids jsonb;
    edge record;
    mirror_id text;
    mirror_count integer:=0;
    edge_count integer;
    typ text;
    model text;
    finite_ids jsonb;
    holders jsonb;
    discovered text[]:=ARRAY[]::text[];
    project_id text;
    native jsonb;
    held jsonb;
    receipts jsonb[]:=ARRAY[]::jsonb[];
    keys text[]:=ARRAY[]::text[];
    source jsonb;
    used_rows integer:=2;
    used_reads integer:=1;
    n bigint;
    cap integer;
    bytes bigint:=2;
    forbidden constant text:=U&'[:#*\0001-\0020\007F-\00A0\1680\2000-\200A\2028\2029\202F\205F\3000]';
BEGIN
    IF jsonb_typeof(p_plan->'items') IS DISTINCT FROM 'array'
        OR jsonb_typeof(p_plan->'holders') IS DISTINCT FROM 'array'
        OR jsonb_typeof(p_census->'members') IS DISTINCT FROM 'array'
        OR jsonb_typeof(p_census->'ledger') IS DISTINCT FROM 'array'
        OR p_plan->'catalog_id' IS DISTINCT FROM proof->'catalog_id'
        OR (p_expected IS NOT NULL AND (jsonb_typeof(p_expected->'all_native') IS DISTINCT FROM 'boolean'
            OR jsonb_typeof(p_expected->'nested_types') IS DISTINCT FROM 'array'
            OR jsonb_typeof(p_expected->'finite_ids') IS DISTINCT FROM 'array'
            OR jsonb_typeof(p_expected->'projects') IS DISTINCT FROM 'object')) THEN
        RAISE EXCEPTION 'invalid role member project census' USING ERRCODE='42501';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096
        OR octet_length(p_census::text)>8388608 OR octet_length(p_plan::text)>8388608 OR octet_length(p_expected::text)>8388608 THEN
        RAISE EXCEPTION 'role member project census exceeds input budget' USING ERRCODE='54000';
    END IF;
    used_rows:=used_rows+jsonb_array_length(p_plan->'items')+jsonb_array_length(p_plan->'holders')
        +jsonb_array_length(p_census->'members')+jsonb_array_length(p_census->'ledger');
    IF used_rows>p_rows THEN RAISE EXCEPTION 'role member project plan exceeds budget' USING ERRCODE='54000';END IF;
    SELECT coalesce(bool_or(i->>'child_type'='iam.project'
            OR (i->>'read_type'='iam.project' AND i->>'guard' IS DISTINCT FROM 'objects')),false),
        coalesce(sum(CASE WHEN i->>'read_type'='iam.project' AND i->>'guard'='objects'
            THEN jsonb_array_length(i->'object_ids') ELSE 0 END),0)
        INTO all_native,n FROM jsonb_array_elements(p_plan->'items') i;
    IF n>p_rows-used_rows THEN RAISE EXCEPTION 'finite project positions exceed budget' USING ERRCODE='54000';END IF;
    used_rows:=used_rows+n::integer;
    SELECT coalesce(jsonb_object_agg(h->>'binding_id',true),'{}'::jsonb) INTO holders FROM jsonb_array_elements(p_plan->'holders') h;
    -- Ранее материализованная координата остаётся в чтении для удаления последней выдачи.
    SELECT coalesce(jsonb_agg(id ORDER BY id COLLATE "C"),'[]'::jsonb) INTO finite_ids FROM (
        SELECT (h#>>'{scope_root,1}') COLLATE "C" AS id FROM jsonb_array_elements(p_plan->'holders') h
            WHERE h#>>'{scope_root,0}'='iam.project'
        UNION
        SELECT v.id COLLATE "C" FROM jsonb_array_elements(p_plan->'items') i
            CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN i->>'read_type'='iam.project' AND i->>'guard'='objects'
                THEN i->'object_ids' ELSE '[]'::jsonb END) v(id)
        UNION
        SELECT (m#>>'{2,object_id}') COLLATE "C" FROM jsonb_array_elements(p_census->'members') m
            WHERE holders ? (m#>>'{2,binding_id}') AND m#>>'{2,object_type}'='iam.project'
        UNION
        SELECT (l#>>'{2,member_object_id}') COLLATE "C" FROM jsonb_array_elements(p_census->'ledger') l
            WHERE holders ? (l#>>'{2,binding_id}') AND l#>>'{2,source}'='member' AND l#>>'{2,member_object_type}'='iam.project'
    ) pos;
    SELECT coalesce(jsonb_agg(t ORDER BY t COLLATE "C"),'[]'::jsonb) INTO nested_types
        FROM (SELECT DISTINCT (i->>'read_type') COLLATE "C" t FROM jsonb_array_elements(p_plan->'items') i
            WHERE i->>'child_type'='iam.project') types;
    IF p_expected IS NOT NULL THEN
        IF NOT ((p_expected->'nested_types') @> nested_types) OR (all_native AND p_expected->'all_native'<>'true'::jsonb)
            OR NOT ((p_expected->'finite_ids') @> finite_ids) THEN
            RAISE EXCEPTION 'role member project positions changed' USING ERRCODE='40001';
        END IF;
        all_native:=(p_expected->>'all_native')::boolean;
        finite_ids:=p_expected->'finite_ids';
        nested_types:=p_expected->'nested_types';
    END IF;
    IF all_native OR finite_ids<>'[]'::jsonb THEN
        IF p_rows-used_rows<5 OR p_reads-used_reads<4 THEN
            RAISE EXCEPTION 'role member project sources exceed budget' USING ERRCODE='54000';
        END IF;
        -- Порядок блокировок общий с чтением графа. SHARE на родной таблице
        -- удерживает полный список и пустые точечные чтения до конца TX.
        LOCK TABLE ONLY kaname.catalog_resource, ONLY kaname.resource_mirror, ONLY kaname.resource_parent_edge
            IN SHARE MODE NOWAIT;
        LOCK TABLE ONLY kaname.projects IN SHARE MODE NOWAIT;
        IF NOT EXISTS(SELECT FROM pg_class c WHERE c.oid='kaname.projects'::regclass
            AND c.relowner=current_user::regrole AND c.relkind='r' AND c.relpersistence='p'
            AND NOT (c.relispartition OR c.relrowsecurity OR c.relforcerowsecurity OR c.relhasrules)
            AND NOT EXISTS(SELECT FROM pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid)
            AND has_table_privilege((proof->>'invoker_oid')::oid,c.oid,'SELECT')
            AND EXISTS(SELECT FROM pg_index i JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=i.indkey[0]
                JOIN pg_class idx ON idx.oid=i.indexrelid JOIN pg_am am ON am.oid=idx.relam
                WHERE i.indrelid=c.oid AND a.attname='id' AND am.amname='btree' AND i.indisprimary
                    AND i.indisready AND i.indisvalid AND i.indimmediate AND i.indnkeyatts=1
                    AND i.indpred IS NULL AND i.indexprs IS NULL)) THEN
            RAISE EXCEPTION 'role member project source custody differs' USING ERRCODE='42501';
        END IF;
        used_rows:=used_rows+5;
        used_reads:=used_reads+4;
    END IF;
    IF all_native THEN
        IF used_reads>=p_reads THEN RAISE EXCEPTION 'project enumeration read budget exhausted' USING ERRCODE='54000';END IF;
        used_reads:=used_reads+1;
        -- На каждую найденную строку требуется как минимум точечное чтение и
        -- полная проверка родной строки и зеркала. Неполная выборка запрещена.
        cap:=least((p_rows-used_rows)/15,(p_reads-used_reads)/7);
        FOR project_id IN SELECT p.id FROM ONLY kaname.projects p LIMIT cap+1 LOOP
            IF cardinality(discovered)>=cap OR octet_length(project_id)>16384 THEN
                RAISE EXCEPTION 'role member project enumeration exceeds budget' USING ERRCODE='54000';
            END IF;
            bytes:=bytes+octet_length(project_id)+4;
            IF bytes>8388608 THEN RAISE EXCEPTION 'project identity bytes exceed budget' USING ERRCODE='54000';END IF;
            discovered:=array_append(discovered,project_id);
            used_rows:=used_rows+1;
        END LOOP;
    END IF;
    IF nested_types<>'[]'::jsonb THEN
        -- DescendantsOf допускает зеркало с ребром без родного проекта.
        -- Эту координату нельзя выдать за отсутствующую или сертифицировать
        -- родным графом. Проверяем и пустой набор под теми же оградами.
        IF NOT all_native OR p_reads-used_reads<4 OR p_rows-used_rows<6 THEN
            RAISE EXCEPTION 'nested project sources exceed budget' USING ERRCODE='54000';
        END IF;
        IF EXISTS(SELECT FROM (VALUES
            ('kaname.catalog_resource'::regclass,ARRAY['dotted','live']),
            ('kaname.resource_mirror'::regclass,ARRAY['object_type','object_id']),
            ('kaname.resource_parent_edge'::regclass,ARRAY['object_type','object_id','depth'])
        ) AS src(rel,cols) WHERE NOT EXISTS(SELECT FROM pg_class c WHERE c.oid=src.rel
            AND c.relowner=current_user::regrole AND c.relkind='r' AND c.relpersistence='p'
            AND NOT (c.relispartition OR c.relrowsecurity OR c.relforcerowsecurity OR c.relhasrules)
            AND NOT EXISTS(SELECT FROM pg_inherits h WHERE h.inhparent=c.oid OR h.inhrelid=c.oid)
            AND has_table_privilege((proof->>'invoker_oid')::oid,c.oid,'SELECT')
            AND EXISTS(SELECT FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid JOIN pg_am am ON am.oid=idx.relam
                WHERE i.indrelid=c.oid AND am.amname='btree' AND i.indisunique AND i.indisvalid AND i.indisready
                    AND i.indimmediate AND i.indpred IS NULL AND i.indexprs IS NULL AND
                    (SELECT array_agg(a.attname::text ORDER BY k.pos) FROM unnest(i.indkey::smallint[]) WITH ORDINALITY k(att,pos)
                     JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=k.att WHERE k.pos<=i.indnkeyatts)=src.cols))) THEN
            RAISE EXCEPTION 'nested project relation custody differs' USING ERRCODE='42501';
        END IF;
        used_reads:=used_reads+4;
        used_rows:=used_rows+6;
        SELECT c.object_type,jsonb_build_array(c.xmin::text,c.ctid::text,c.dotted,c.object_type)
            INTO project_model,catalog_image FROM ONLY kaname.catalog_resource c WHERE c.dotted='iam.project' AND c.live;
        bytes:=bytes+coalesce(octet_length(catalog_image::text),4)+16;
        IF bytes>8388608 THEN RAISE EXCEPTION 'nested project catalog bytes exceed budget' USING ERRCODE='54000';END IF;
        catalog_images:=jsonb_build_object('iam.project',catalog_image);
        parent_models:='{}'::jsonb;
        FOR typ IN SELECT value FROM jsonb_array_elements_text(nested_types) LOOP
            IF used_rows>=p_rows OR used_reads>=p_reads THEN RAISE EXCEPTION 'nested catalog exceeds budget' USING ERRCODE='54000';END IF;
            used_reads:=used_reads+1;
            used_rows:=used_rows+1;
            SELECT c.object_type,jsonb_build_array(c.xmin::text,c.ctid::text,c.dotted,c.object_type)
                INTO model,catalog_image FROM ONLY kaname.catalog_resource c WHERE c.dotted=typ AND c.live;
            bytes:=bytes+coalesce(octet_length(catalog_image::text),4)+octet_length(typ)+4;
            IF bytes>8388608 THEN RAISE EXCEPTION 'nested parent catalog bytes exceed budget' USING ERRCODE='54000';END IF;
            catalog_images:=catalog_images||jsonb_build_object(typ,catalog_image);
            IF model IS NOT NULL THEN
                IF octet_length(model) NOT BETWEEN 1 AND 16384 OR model COLLATE "C" ~ forbidden THEN
                    RAISE EXCEPTION 'invalid nested catalog model' USING ERRCODE='42501';
                END IF;
                parent_models:=parent_models||jsonb_build_object(model,true);
            END IF;
        END LOOP;
        IF project_model IS NOT NULL AND parent_models<>'{}'::jsonb THEN
            IF used_reads>=p_reads OR octet_length(project_model) NOT BETWEEN 1 AND 16384 OR project_model COLLATE "C" ~ forbidden THEN
                RAISE EXCEPTION 'nested project mirror scope exceeds budget' USING ERRCODE='54000';
            END IF;
            used_reads:=used_reads+1;
            SELECT coalesce(jsonb_object_agg(id,true),'{}'::jsonb) INTO native_ids FROM unnest(discovered) id;
            cap:=p_rows-used_rows;
            FOR mirror_id IN SELECT m.object_id FROM ONLY kaname.resource_mirror m WHERE m.object_type='iam.project' LIMIT cap+1 LOOP
                mirror_count:=mirror_count+1;
                IF used_rows>=p_rows OR mirror_count>cap OR octet_length(mirror_id)>16384 THEN
                    RAISE EXCEPTION 'nested mirror enumeration exceeds budget' USING ERRCODE='54000';
                END IF;
                used_rows:=used_rows+1;
                IF native_ids ? mirror_id THEN CONTINUE;END IF;
                IF used_reads>=p_reads THEN RAISE EXCEPTION 'nested project edge reads exceed budget' USING ERRCODE='54000';END IF;
                used_reads:=used_reads+1;
                edge_count:=0;
                FOR edge IN SELECT e.parent_type FROM ONLY kaname.resource_parent_edge e
                    WHERE e.object_type=project_model AND e.object_id=mirror_id ORDER BY e.depth LIMIT 5 LOOP
                    edge_count:=edge_count+1;
                    IF used_rows>=p_rows OR edge_count>4 THEN RAISE EXCEPTION 'nested project edge bound exceeded' USING ERRCODE='54000';END IF;
                    used_rows:=used_rows+1;
                    IF parent_models ? edge.parent_type THEN
                        RAISE EXCEPTION 'nested project mirror and edge lack a native project' USING ERRCODE='40001';
                    END IF;
                END LOOP;
            END LOOP;
        END IF;
    END IF;
    IF jsonb_array_length(finite_ids)>p_rows-used_rows THEN
        RAISE EXCEPTION 'role member project union exceeds budget' USING ERRCODE='54000';
    END IF;
    used_rows:=used_rows+jsonb_array_length(finite_ids);
    FOR project_id IN SELECT id FROM (
        SELECT id COLLATE "C" AS id FROM unnest(discovered) id
        UNION SELECT id COLLATE "C" FROM jsonb_array_elements_text(finite_ids) id) candidates ORDER BY id COLLATE "C"
    LOOP
        IF coalesce(project_id,'')='' OR octet_length(project_id)>16384 OR project_id COLLATE "C" ~ forbidden THEN
            RAISE EXCEPTION 'invalid role member project identity' USING ERRCODE='42501';
        END IF;
        IF used_rows>=p_rows OR used_reads>=p_reads THEN
            RAISE EXCEPTION 'role member project row exceeds budget' USING ERRCODE='54000';
        END IF;
        used_rows:=used_rows+1;
        used_reads:=used_reads+1;
        SELECT jsonb_build_array(p.xmin::text,p.ctid::text,to_jsonb(p)) INTO native
            FROM ONLY kaname.projects p WHERE p.id=project_id FOR SHARE OF p NOWAIT;
        held:='null'::jsonb;
        IF native IS NOT NULL THEN
            held:=kaname._authority_role_move_project_member_graph_hold_v1(project_id,native,p_rows-used_rows,p_reads-used_reads);
            used_rows:=used_rows+(held->>'rows')::integer;
            used_reads:=used_reads+(held->>'reads')::integer;
        END IF;
        IF p_expected IS NOT NULL AND (p_expected->'projects'->project_id) IS DISTINCT FROM held THEN
            RAISE EXCEPTION 'role member project graph changed' USING ERRCODE='40001';
        END IF;
        bytes:=bytes+octet_length(held::text)+octet_length(project_id)+4;
        IF bytes>8388608 THEN RAISE EXCEPTION 'role member project receipts exceed byte budget' USING ERRCODE='54000';END IF;
        keys:=array_append(keys,project_id);
        receipts:=array_append(receipts,held);
    END LOOP;
    SELECT jsonb_build_object('all_native',all_native,'nested_types',nested_types,'nested_catalog',catalog_images,'finite_ids',finite_ids,'projects',
        coalesce(jsonb_object_agg(k.id,k.held),'{}'::jsonb)) INTO source FROM unnest(keys,receipts) k(id,held);
    IF octet_length(source::text)>8388608 THEN RAISE EXCEPTION 'role member project receipt exceeds bound' USING ERRCODE='54000';END IF;
    IF p_expected IS NOT NULL AND source IS DISTINCT FROM p_expected THEN
        RAISE EXCEPTION 'role member project census changed' USING ERRCODE='40001';
    END IF;
    RETURN jsonb_build_object('source',source,'rows',used_rows,'reads',used_reads);
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'role member project source busy' USING ERRCODE='40001';
END;
$universe$;

DO $private$
DECLARE grantee record;fn regprocedure:='kaname._authority_role_move_member_projects_v1(jsonb,jsonb,jsonb,integer,integer)'::regprocedure;
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
        ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','780972ca904bcf3d09f504fa405b4e375f58c2fc7cfc026708df286059ec589c','89aa9d6ed2bc4c6edb63c9c06ff3e8f30aee3efa45e776b1fd1fa3810c1722a2',$changes$[
  [
    "    positions jsonb;",
    "    positions jsonb;\n    member_projects jsonb;"
  ],
  [
    "    IF octet_length(frozen::text)>8388608 THEN",
    "    member_projects:=kaname._authority_role_move_member_projects_v1(\n        coalesce(predicates->'plan',jsonb_build_object('catalog_id',proof->'catalog_id','items','[]'::jsonb,'holders','[]'::jsonb)),\n        frozen->'binding_census',NULL,p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(member_projects->>'rows')::integer;\n    used_reads:=used_reads+(member_projects->>'reads')::integer;\n    frozen:=frozen||jsonb_build_object('member_projects',member_projects->'source');\n    IF octet_length(frozen::text)>8388608 THEN"
  ]
]$changes$::jsonb),
        ('_authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)','de4d128e08cb26f3762f97f89953459ba1c7037e16b070c647eb87eb180ea1e2','9af62dcdbd730555e6e297e7ade8cbc0c656f946654258196c6289bb707d1c75',$changes$[
  [
    "    positions jsonb;",
    "    positions jsonb;\n    member_projects jsonb;"
  ],
  [
    "    result:=kaname._authority_role_move_copy_requirements_require_v1",
    "    IF jsonb_typeof(p_frozen->'member_projects') IS DISTINCT FROM 'object' THEN\n        RAISE EXCEPTION 'prepared role member project census missing' USING ERRCODE='42501';\n    END IF;\n    member_projects:=kaname._authority_role_move_member_projects_v1(\n        predicates->'plan',p_frozen->'binding_census',p_frozen->'member_projects',p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(member_projects->>'rows')::integer;\n    used_reads:=used_reads+(member_projects->>'reads')::integer;\n    result:=kaname._authority_role_move_copy_requirements_require_v1"
  ],
  [
    "        'local_label_candidates',local_labels",
    "        'member_projects_sha256',encode(sha256(convert_to((member_projects->'source')::text,'UTF8')),'hex'),\n        'local_label_candidates',local_labels"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','4dc3636ac3c97ab3e0f0d04044aac6c7a8886e4debeccdfe5d558ecef6bbadf5','68d117b6176dc3e08f00edd4ea26d1f0503215f81e3f873ceb6bdad75b866df0',$changes$[
  [
    "780972ca904bcf3d09f504fa405b4e375f58c2fc7cfc026708df286059ec589c",
    "89aa9d6ed2bc4c6edb63c9c06ff3e8f30aee3efa45e776b1fd1fa3810c1722a2"
  ],
  [
    "de4d128e08cb26f3762f97f89953459ba1c7037e16b070c647eb87eb180ea1e2",
    "9af62dcdbd730555e6e297e7ade8cbc0c656f946654258196c6289bb707d1c75"
  ],
  [
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n",
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n ('_authority_role_move_member_projects_v1(jsonb,jsonb,jsonb,integer,integer)','5eccdddd9492815a4ee47c0a3f2e3110cec234d7cef7606cddbee3fef2a40f15',false,'v',true,'private'),\n"
  ],
  [
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n",
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n  ('_authority_role_move_member_projects_v1(jsonb,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_plan','p_census','p_expected','p_rows','p_reads']),\n"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','ac07d7770b588e8a0c0ae4085d61389680ed2ce61477c1a55cd3416d44647ef1','3744bc50c9796c33fed950cca61de59ec25979e5ea7aa64be4a19f3adcaf4ec0',$changes$[
  [
    "4dc3636ac3c97ab3e0f0d04044aac6c7a8886e4debeccdfe5d558ecef6bbadf5",
    "68d117b6176dc3e08f00edd4ea26d1f0503215f81e3f873ceb6bdad75b866df0"
  ]
]$changes$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','969eacfded994b5007bd341e68e4a11a0eb1b20cdec7be141373d26771a68be7','b4a21cc93994221c808eb9f62542e40521c38edd2eadd5262cb8e10339032ec5',$changes$[
  [
    "4dc3636ac3c97ab3e0f0d04044aac6c7a8886e4debeccdfe5d558ecef6bbadf5",
    "68d117b6176dc3e08f00edd4ea26d1f0503215f81e3f873ceb6bdad75b866df0"
  ],
  [
    "ac07d7770b588e8a0c0ae4085d61389680ed2ce61477c1a55cd3416d44647ef1",
    "3744bc50c9796c33fed950cca61de59ec25979e5ea7aa64be4a19f3adcaf4ec0"
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
        ('authority_metadata_service_account_access_label_ready_v1()','b4a21cc93994221c808eb9f62542e40521c38edd2eadd5262cb8e10339032ec5','969eacfded994b5007bd341e68e4a11a0eb1b20cdec7be141373d26771a68be7',$changes$[
  [
    "3744bc50c9796c33fed950cca61de59ec25979e5ea7aa64be4a19f3adcaf4ec0",
    "ac07d7770b588e8a0c0ae4085d61389680ed2ce61477c1a55cd3416d44647ef1"
  ],
  [
    "68d117b6176dc3e08f00edd4ea26d1f0503215f81e3f873ceb6bdad75b866df0",
    "4dc3636ac3c97ab3e0f0d04044aac6c7a8886e4debeccdfe5d558ecef6bbadf5"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','3744bc50c9796c33fed950cca61de59ec25979e5ea7aa64be4a19f3adcaf4ec0','ac07d7770b588e8a0c0ae4085d61389680ed2ce61477c1a55cd3416d44647ef1',$changes$[
  [
    "68d117b6176dc3e08f00edd4ea26d1f0503215f81e3f873ceb6bdad75b866df0",
    "4dc3636ac3c97ab3e0f0d04044aac6c7a8886e4debeccdfe5d558ecef6bbadf5"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','68d117b6176dc3e08f00edd4ea26d1f0503215f81e3f873ceb6bdad75b866df0','4dc3636ac3c97ab3e0f0d04044aac6c7a8886e4debeccdfe5d558ecef6bbadf5',$changes$[
  [
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n  ('_authority_role_move_member_projects_v1(jsonb,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_plan','p_census','p_expected','p_rows','p_reads']),\n",
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n"
  ],
  [
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n ('_authority_role_move_member_projects_v1(jsonb,jsonb,jsonb,integer,integer)','5eccdddd9492815a4ee47c0a3f2e3110cec234d7cef7606cddbee3fef2a40f15',false,'v',true,'private'),\n",
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n"
  ],
  [
    "9af62dcdbd730555e6e297e7ade8cbc0c656f946654258196c6289bb707d1c75",
    "de4d128e08cb26f3762f97f89953459ba1c7037e16b070c647eb87eb180ea1e2"
  ],
  [
    "89aa9d6ed2bc4c6edb63c9c06ff3e8f30aee3efa45e776b1fd1fa3810c1722a2",
    "780972ca904bcf3d09f504fa405b4e375f58c2fc7cfc026708df286059ec589c"
  ]
]$changes$::jsonb),
        ('_authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)','9af62dcdbd730555e6e297e7ade8cbc0c656f946654258196c6289bb707d1c75','de4d128e08cb26f3762f97f89953459ba1c7037e16b070c647eb87eb180ea1e2',$changes$[
  [
    "        'member_projects_sha256',encode(sha256(convert_to((member_projects->'source')::text,'UTF8')),'hex'),\n        'local_label_candidates',local_labels",
    "        'local_label_candidates',local_labels"
  ],
  [
    "    IF jsonb_typeof(p_frozen->'member_projects') IS DISTINCT FROM 'object' THEN\n        RAISE EXCEPTION 'prepared role member project census missing' USING ERRCODE='42501';\n    END IF;\n    member_projects:=kaname._authority_role_move_member_projects_v1(\n        predicates->'plan',p_frozen->'binding_census',p_frozen->'member_projects',p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(member_projects->>'rows')::integer;\n    used_reads:=used_reads+(member_projects->>'reads')::integer;\n    result:=kaname._authority_role_move_copy_requirements_require_v1",
    "    result:=kaname._authority_role_move_copy_requirements_require_v1"
  ],
  [
    "    positions jsonb;\n    member_projects jsonb;",
    "    positions jsonb;"
  ]
]$changes$::jsonb),
        ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','89aa9d6ed2bc4c6edb63c9c06ff3e8f30aee3efa45e776b1fd1fa3810c1722a2','780972ca904bcf3d09f504fa405b4e375f58c2fc7cfc026708df286059ec589c',$changes$[
  [
    "    member_projects:=kaname._authority_role_move_member_projects_v1(\n        coalesce(predicates->'plan',jsonb_build_object('catalog_id',proof->'catalog_id','items','[]'::jsonb,'holders','[]'::jsonb)),\n        frozen->'binding_census',NULL,p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(member_projects->>'rows')::integer;\n    used_reads:=used_reads+(member_projects->>'reads')::integer;\n    frozen:=frozen||jsonb_build_object('member_projects',member_projects->'source');\n    IF octet_length(frozen::text)>8388608 THEN",
    "    IF octet_length(frozen::text)>8388608 THEN"
  ],
  [
    "    positions jsonb;\n    member_projects jsonb;",
    "    positions jsonb;"
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

DROP FUNCTION kaname._authority_role_move_member_projects_v1(jsonb,jsonb,jsonb,integer,integer);
