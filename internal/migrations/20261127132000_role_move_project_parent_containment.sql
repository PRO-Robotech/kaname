-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Набор областей родителя восстанавливается по тем же родным строкам и
-- зеркалам, что и MatchDescendants. Удерживаем также отсутствие и поколения
-- всех строк, от которых зависит включение, прежде чем читать обратные рёбра.
CREATE FUNCTION kaname._authority_role_move_parent_containment_v1(p_type text,p_id text,p_scopes jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $containment$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    src regclass;
    rel regclass;
    cols text[];
    locks regclass[];
    image jsonb;
    fallback jsonb;
    project_id text;
    row_image jsonb;
    images jsonb[]:=ARRAY[]::jsonb[];
    membership_states jsonb:='[]'::jsonb;
    src_index jsonb;
    projection jsonb;
    source jsonb;
    scope jsonb;
    included boolean:=false;
    cap integer;
    bytes bigint:=2;
    used_rows integer:=3;used_reads integer:=2;
BEGIN
    IF coalesce(p_type,'')='' OR coalesce(p_id,'')='' OR octet_length(p_id)>16384 OR octet_length(p_type)>16384
        OR jsonb_typeof(p_scopes) IS DISTINCT FROM 'array' OR jsonb_array_length(p_scopes)=0 THEN
        RAISE EXCEPTION 'invalid member project parent containment' USING ERRCODE='42501';
    END IF;
    used_rows:=used_rows+jsonb_array_length(p_scopes);
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096
        OR octet_length(p_scopes::text)>8388608 THEN RAISE EXCEPTION 'parent containment input exceeds budget' USING ERRCODE='54000';END IF;
    src:=CASE p_type WHEN 'iam.account' THEN 'kaname.accounts'::regclass WHEN 'iam.project' THEN 'kaname.projects'::regclass
        WHEN 'iam.role' THEN 'kaname.roles'::regclass WHEN 'iam.group' THEN 'kaname.groups'::regclass
        WHEN 'iam.serviceAccount' THEN 'kaname.service_accounts'::regclass WHEN 'iam.accessBinding' THEN 'kaname.access_bindings'::regclass
        WHEN 'iam.user' THEN 'kaname.users'::regclass ELSE 'kaname.resource_mirror'::regclass END;
    locks:=ARRAY['kaname.projects'::regclass];
    IF src<>locks[1] THEN locks:=array_append(locks,src);END IF;
    IF p_type='iam.user' THEN locks:=array_append(locks,'kaname.memberships'::regclass);END IF;
    FOREACH rel IN ARRAY locks LOOP
        IF p_rows-used_rows<2 OR p_reads-used_reads<2 THEN RAISE EXCEPTION 'parent containment custody exceeds budget' USING ERRCODE='54000';END IF;
        used_rows:=used_rows+2;used_reads:=used_reads+2;
        EXECUTE format('LOCK TABLE ONLY %s IN SHARE MODE NOWAIT',rel);
        cols:=CASE rel WHEN 'kaname.resource_mirror'::regclass THEN ARRAY['object_type','object_id']
            WHEN 'kaname.memberships'::regclass THEN ARRAY['user_id','account_id'] ELSE ARRAY['id'] END;
        IF NOT EXISTS(SELECT FROM pg_class c WHERE c.oid=rel AND c.relowner=current_user::regrole
            AND c.relkind='r' AND c.relpersistence='p' AND NOT (c.relispartition OR c.relrowsecurity OR c.relforcerowsecurity OR c.relhasrules)
            AND NOT EXISTS(SELECT FROM pg_inherits h WHERE h.inhparent=c.oid OR h.inhrelid=c.oid)
            AND has_table_privilege((proof->>'invoker_oid')::oid,c.oid,'SELECT')
            AND EXISTS(SELECT FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid JOIN pg_am am ON am.oid=idx.relam
                WHERE i.indrelid=c.oid AND am.amname='btree' AND i.indisunique AND i.indisvalid AND i.indisready AND i.indimmediate
                    AND i.indpred IS NULL AND i.indexprs IS NULL AND
                    (SELECT array_agg(a.attname::text ORDER BY k.pos) FROM unnest(i.indkey::smallint[]) WITH ORDINALITY k(att,pos)
                    JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=k.att WHERE k.pos<=i.indnkeyatts)=cols)) THEN
            RAISE EXCEPTION 'parent containment source custody differs' USING ERRCODE='42501';
        END IF;
    END LOOP;
    IF used_rows>=p_rows OR used_reads>=p_reads THEN RAISE EXCEPTION 'parent containment row exceeds budget' USING ERRCODE='54000';END IF;
    used_rows:=used_rows+1;used_reads:=used_reads+1;
    IF src='kaname.resource_mirror'::regclass THEN
        SELECT jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) INTO image FROM ONLY kaname.resource_mirror m
            WHERE m.object_type=p_type AND m.object_id=p_id;
        project_id:=image#>>'{2,parent_project_id}';
    ELSE
        EXECUTE format('SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r)) FROM ONLY %s r WHERE r.id=$1',src)
            INTO image USING p_id;
        project_id:=CASE p_type WHEN 'iam.project' THEN p_id WHEN 'iam.role' THEN image#>>'{2,project_id}'
            WHEN 'iam.accessBinding' THEN CASE WHEN image#>>'{2,resource_type}'='project' THEN image#>>'{2,resource_id}' END END;
    END IF;
    bytes:=bytes+coalesce(octet_length(image::text),4);
    IF bytes>8388608 THEN RAISE EXCEPTION 'parent image exceeds byte budget' USING ERRCODE='54000';END IF;
    src_index:=jsonb_build_object(jsonb_build_array(CASE WHEN src='kaname.resource_mirror'::regclass THEN 2 ELSE 30 END,p_type,p_id,'')::text,
        jsonb_build_object('source','{}'::jsonb,'states',CASE WHEN image IS NULL THEN '[]'::jsonb ELSE jsonb_build_array(image) END));
    IF image IS NOT NULL AND coalesce(project_id,'')<>'' THEN
        IF p_type='iam.project' THEN fallback:=image;
        ELSE
            IF used_rows>=p_rows OR used_reads>=p_reads THEN RAISE EXCEPTION 'parent owning project exceeds budget' USING ERRCODE='54000';END IF;
            used_rows:=used_rows+1;used_reads:=used_reads+1;
            SELECT jsonb_build_array(p.xmin::text,p.ctid::text,to_jsonb(p)) INTO fallback FROM ONLY kaname.projects p WHERE p.id=project_id;
        END IF;
        bytes:=bytes+coalesce(octet_length(fallback::text),4);
        IF bytes>8388608 THEN RAISE EXCEPTION 'parent owning project exceeds byte budget' USING ERRCODE='54000';END IF;
        src_index:=src_index||jsonb_build_object(jsonb_build_array(1,'project',project_id,'')::text,jsonb_build_object('source','{}'::jsonb,
            'states',CASE WHEN fallback IS NULL THEN '[]'::jsonb ELSE jsonb_build_array(fallback) END));
    END IF;
    IF p_type='iam.user' AND image IS NOT NULL THEN
        IF used_reads>=p_reads THEN RAISE EXCEPTION 'parent memberships exceed budget' USING ERRCODE='54000';END IF;
        used_reads:=used_reads+1;cap:=p_rows-used_rows;
        FOR row_image IN SELECT jsonb_build_array(m.xmin::text,m.ctid::text,jsonb_build_object('user_id',m.user_id,'account_id',m.account_id))
            FROM ONLY kaname.memberships m WHERE m.user_id=p_id ORDER BY m.account_id LIMIT cap+1 LOOP
            IF used_rows>=p_rows THEN RAISE EXCEPTION 'parent memberships exceed row budget' USING ERRCODE='54000';END IF;
            used_rows:=used_rows+1;bytes:=bytes+octet_length(row_image::text)+2;
            IF bytes>8388608 THEN RAISE EXCEPTION 'parent memberships exceed byte budget' USING ERRCODE='54000';END IF;
            images:=array_append(images,row_image);
        END LOOP;
        membership_states:=to_jsonb(images);
        src_index:=src_index||jsonb_build_object(jsonb_build_array(31,p_type,p_id,'')::text,jsonb_build_object('source','{}'::jsonb,'states',membership_states));
    END IF;
    projection:=kaname._authority_resource_projection_v2(src_index,p_type,p_id);
    FOR scope IN SELECT value FROM jsonb_array_elements(p_scopes) LOOP
        IF jsonb_typeof(scope) IS DISTINCT FROM 'array' OR jsonb_array_length(scope)<>2 OR coalesce(scope->>0,'') NOT IN ('account','project','cluster')
            OR coalesce(scope->>1,'')='' THEN RAISE EXCEPTION 'invalid parent scope' USING ERRCODE='42501';END IF;
        IF projection->'present'='true'::jsonb AND kaname._authority_resource_contained_v2(scope->>0,scope->>1,
            projection->'current_accounts',projection->>'current_project') THEN included:=true;END IF;
    END LOOP;
    source:=jsonb_build_object('present',projection->'present','included',included,'scopes',p_scopes,'sha256',
        encode(sha256(convert_to(src_index::text,'UTF8')),'hex'));
    RETURN jsonb_build_object('source',source,'rows',used_rows,'reads',used_reads,'bytes',bytes);
EXCEPTION WHEN lock_not_available THEN RAISE EXCEPTION 'member project parent source busy' USING ERRCODE='40001';
END;
$containment$;

DO $private$
DECLARE grantee record;fn regprocedure:='kaname._authority_role_move_parent_containment_v1(text,text,jsonb,integer,integer)'::regprocedure;
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
        ('_authority_role_move_member_projects_v1(jsonb,jsonb,jsonb,integer,integer)','e1f118fe1f1be00d7d662acb352c6599e94e51b7ca14b569bbf25fccb93d78e2','34302001c988cfc77693679fc4c74cc7a3dce511e7f241b160917e58272dd73b',$changes$[
  [
    "    finite_parents jsonb;",
    "    finite_parents jsonb;\n    parent_scopes jsonb;\n    parent_states jsonb:='{}'::jsonb;\n    contained jsonb;\n    wide_scopes jsonb;\n    inspected jsonb:='{}'::jsonb;"
  ],
  [
    "            OR jsonb_typeof(p_expected->'parent_edges')",
    "            OR jsonb_typeof(p_expected->'parent_scopes') IS DISTINCT FROM 'object'\n            OR jsonb_typeof(p_expected->'parent_states') IS DISTINCT FROM 'object'\n            OR jsonb_typeof(p_expected->'wide_scopes') IS DISTINCT FROM 'object'\n            OR jsonb_typeof(p_expected->'parent_edges')"
  ],
  [
    "SELECT typ,scope_id AS id FROM items",
    "SELECT typ,scope_id AS id,jsonb_build_array(scope_kind,scope_id) AS scope FROM items"
  ],
  [
    "SELECT typ,v.id FROM items CROSS",
    "SELECT typ,v.id,jsonb_build_array(scope_kind,scope_id) FROM items CROSS"
  ],
  [
    "), distinct_parents AS (SELECT DISTINCT typ COLLATE \"C\" typ,id COLLATE \"C\" id FROM parents)",
    "),\n    distinct_parents AS (SELECT DISTINCT typ COLLATE \"C\" typ,id COLLATE \"C\" id,scope FROM parents),\n    grouped AS (SELECT typ,id,jsonb_agg(scope ORDER BY scope) scope_list FROM distinct_parents GROUP BY typ,id)"
  ],
  [
    "        INTO finite_parents FROM distinct_parents;",
    "        ,coalesce(jsonb_object_agg(jsonb_build_array(typ,id)::text,scope_list),'{}'::jsonb)\n        INTO finite_parents,parent_scopes FROM grouped;"
  ],
  [
    "    SELECT coalesce(jsonb_agg(t ORDER BY t COLLATE \"C\"),'[]'::jsonb) INTO nested_types FROM (",
    "    WITH distinct_wide AS ("
  ],
  [
    "SELECT DISTINCT (i->>'read_type') COLLATE \"C\" t FROM jsonb_array_elements(p_plan->'items') i",
    "SELECT DISTINCT (i->>'read_type') COLLATE \"C\" t,i->'scope' scope FROM jsonb_array_elements(p_plan->'items') i"
  ],
  [
    "    ) types;\n    SELECT nested_types",
    "    ), grouped AS (SELECT t,jsonb_agg(scope ORDER BY scope) scopes FROM distinct_wide GROUP BY t)\n    SELECT coalesce(jsonb_agg(t ORDER BY t COLLATE \"C\"),'[]'::jsonb),coalesce(jsonb_object_agg(t,scopes),'{}'::jsonb)\n        INTO nested_types,wide_scopes FROM grouped;\n    SELECT nested_types"
  ],
  [
    "WHERE NOT (p_expected->'parent_edges' ? (r::text)))",
    "WHERE NOT (p_expected->'parent_states' ? (r::text)))\n            OR EXISTS(SELECT FROM jsonb_each(parent_scopes) s CROSS JOIN LATERAL jsonb_array_elements(s.value) v\n                WHERE NOT EXISTS(SELECT FROM jsonb_array_elements(p_expected->'parent_scopes'->s.key) old_scope WHERE old_scope=v))\n            OR EXISTS(SELECT FROM jsonb_each(wide_scopes) s CROSS JOIN LATERAL jsonb_array_elements(s.value) v\n                WHERE NOT EXISTS(SELECT FROM jsonb_array_elements(p_expected->'wide_scopes'->s.key) old_scope WHERE old_scope=v))"
  ],
  [
    "        finite_parents:=p_expected->'finite_parents';",
    "        finite_parents:=p_expected->'finite_parents';\n        parent_scopes:=p_expected->'parent_scopes';\n        wide_scopes:=p_expected->'wide_scopes';"
  ],
  [
    "        parent_key:=parent_ref::text;",
    "        parent_key:=parent_ref::text;\n        contained:=kaname._authority_role_move_parent_containment_v1(parent_ref->>0,parent_ref->>1,\n            parent_scopes->parent_key,p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(contained->>'rows')::integer;\n        used_reads:=used_reads+(contained->>'reads')::integer;\n        bytes:=bytes+(contained->>'bytes')::bigint+octet_length(parent_key)+octet_length((contained->'source')::text)+4;\n        IF bytes>8388608 THEN RAISE EXCEPTION 'parent containment evidence exceeds byte budget' USING ERRCODE='54000';END IF;\n        parent_states:=parent_states||jsonb_build_object(parent_key,contained->'source');\n        IF p_expected IS NOT NULL AND p_expected->'parent_states'->parent_key IS DISTINCT FROM contained->'source' THEN\n            RAISE EXCEPTION 'finite parent containment changed' USING ERRCODE='40001';\n        END IF;\n        IF contained#>'{source,included}' IS DISTINCT FROM 'true'::jsonb THEN CONTINUE;END IF;"
  ],
  [
    "parent_models:=parent_models||jsonb_build_object(model,true);",
    "parent_models:=parent_models||jsonb_build_object(model,coalesce(parent_models->model,'[]'::jsonb)||jsonb_build_array(scanned_parent_type));"
  ],
  [
    "                    IF parent_models ? edge.parent_type THEN\n                        RAISE EXCEPTION 'nested project mirror and edge lack a native project' USING ERRCODE='40001';\n                    END IF;",
    "                    FOR scanned_parent_type IN SELECT value FROM jsonb_array_elements_text(parent_models->edge.parent_type) LOOP\n                        parent_key:=jsonb_build_array(scanned_parent_type,edge.parent_id)::text;\n                        IF inspected ? parent_key THEN CONTINUE;END IF;\n                        contained:=kaname._authority_role_move_parent_containment_v1(scanned_parent_type,edge.parent_id,wide_scopes->scanned_parent_type,\n                            p_rows-used_rows,p_reads-used_reads);\n                        used_rows:=used_rows+(contained->>'rows')::integer;\n                        used_reads:=used_reads+(contained->>'reads')::integer;\n                        bytes:=bytes+(contained->>'bytes')::bigint+octet_length(parent_key)+octet_length((contained->'source')::text)+4;\n                        IF bytes>8388608 THEN RAISE EXCEPTION 'wide parent evidence exceeds byte budget' USING ERRCODE='54000';END IF;\n                        IF contained#>'{source,included}'='true'::jsonb THEN\n                            RAISE EXCEPTION 'nested project mirror and edge lack a native project' USING ERRCODE='40001';\n                        END IF;\n                        inspected:=inspected||jsonb_build_object(parent_key,contained->'source');\n                    END LOOP;"
  ],
  [
    "'all_native',all_native,'finite_parents'",
    "'parent_scopes',parent_scopes,'parent_states',parent_states,'wide_scopes',wide_scopes,'wide_excluded',inspected,'all_native',all_native,'finite_parents'"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','8be8f6030fc62b0dddb14e31e6a59e5dc84c7fed58076ae0023aa9819c3f8c10','dd4e3deef26c9d759f4cb7e43a47a70e1aa81e4648bc8751daa6a01713c69d66',$changes$[
  [
    "e1f118fe1f1be00d7d662acb352c6599e94e51b7ca14b569bbf25fccb93d78e2",
    "34302001c988cfc77693679fc4c74cc7a3dce511e7f241b160917e58272dd73b"
  ],
  [
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n",
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n ('_authority_role_move_parent_containment_v1(text,text,jsonb,integer,integer)','a8e69155266903f6a60c263eb9a647a33a1535e98296727637bbd5e91426eb1d',false,'v',true,'private'),\n"
  ],
  [
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n",
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n  ('_authority_role_move_parent_containment_v1(text,text,jsonb,integer,integer)','jsonb',5,ARRAY['p_type','p_id','p_scopes','p_rows','p_reads']),\n"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','00004e4b21a491f8787895c1109aefff0645bafd067857f0a264a302dce147d2','aea7772c5a201f684f0ebfd0c7fff715bf02c8faef4ab3a81554efa08d7a07dc',$changes$[
  [
    "8be8f6030fc62b0dddb14e31e6a59e5dc84c7fed58076ae0023aa9819c3f8c10",
    "dd4e3deef26c9d759f4cb7e43a47a70e1aa81e4648bc8751daa6a01713c69d66"
  ]
]$changes$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','366002c5983dd88798848297d9cb19e85b5ae3f5b8c470ecfb22d3ee05dbf3f7','d67b88ffe3581d55fa2cc391ed7a2af656151108ba5f67fef343d831a6018064',$changes$[
  [
    "8be8f6030fc62b0dddb14e31e6a59e5dc84c7fed58076ae0023aa9819c3f8c10",
    "dd4e3deef26c9d759f4cb7e43a47a70e1aa81e4648bc8751daa6a01713c69d66"
  ],
  [
    "00004e4b21a491f8787895c1109aefff0645bafd067857f0a264a302dce147d2",
    "aea7772c5a201f684f0ebfd0c7fff715bf02c8faef4ab3a81554efa08d7a07dc"
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
        ('authority_metadata_service_account_access_label_ready_v1()','d67b88ffe3581d55fa2cc391ed7a2af656151108ba5f67fef343d831a6018064','366002c5983dd88798848297d9cb19e85b5ae3f5b8c470ecfb22d3ee05dbf3f7',$changes$[
  [
    "aea7772c5a201f684f0ebfd0c7fff715bf02c8faef4ab3a81554efa08d7a07dc",
    "00004e4b21a491f8787895c1109aefff0645bafd067857f0a264a302dce147d2"
  ],
  [
    "dd4e3deef26c9d759f4cb7e43a47a70e1aa81e4648bc8751daa6a01713c69d66",
    "8be8f6030fc62b0dddb14e31e6a59e5dc84c7fed58076ae0023aa9819c3f8c10"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','aea7772c5a201f684f0ebfd0c7fff715bf02c8faef4ab3a81554efa08d7a07dc','00004e4b21a491f8787895c1109aefff0645bafd067857f0a264a302dce147d2',$changes$[
  [
    "dd4e3deef26c9d759f4cb7e43a47a70e1aa81e4648bc8751daa6a01713c69d66",
    "8be8f6030fc62b0dddb14e31e6a59e5dc84c7fed58076ae0023aa9819c3f8c10"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','dd4e3deef26c9d759f4cb7e43a47a70e1aa81e4648bc8751daa6a01713c69d66','8be8f6030fc62b0dddb14e31e6a59e5dc84c7fed58076ae0023aa9819c3f8c10',$changes$[
  [
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n  ('_authority_role_move_parent_containment_v1(text,text,jsonb,integer,integer)','jsonb',5,ARRAY['p_type','p_id','p_scopes','p_rows','p_reads']),\n",
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n"
  ],
  [
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n ('_authority_role_move_parent_containment_v1(text,text,jsonb,integer,integer)','a8e69155266903f6a60c263eb9a647a33a1535e98296727637bbd5e91426eb1d',false,'v',true,'private'),\n",
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n"
  ],
  [
    "34302001c988cfc77693679fc4c74cc7a3dce511e7f241b160917e58272dd73b",
    "e1f118fe1f1be00d7d662acb352c6599e94e51b7ca14b569bbf25fccb93d78e2"
  ]
]$changes$::jsonb),
        ('_authority_role_move_member_projects_v1(jsonb,jsonb,jsonb,integer,integer)','34302001c988cfc77693679fc4c74cc7a3dce511e7f241b160917e58272dd73b','e1f118fe1f1be00d7d662acb352c6599e94e51b7ca14b569bbf25fccb93d78e2',$changes$[
  [
    "'parent_scopes',parent_scopes,'parent_states',parent_states,'wide_scopes',wide_scopes,'wide_excluded',inspected,'all_native',all_native,'finite_parents'",
    "'all_native',all_native,'finite_parents'"
  ],
  [
    "                    FOR scanned_parent_type IN SELECT value FROM jsonb_array_elements_text(parent_models->edge.parent_type) LOOP\n                        parent_key:=jsonb_build_array(scanned_parent_type,edge.parent_id)::text;\n                        IF inspected ? parent_key THEN CONTINUE;END IF;\n                        contained:=kaname._authority_role_move_parent_containment_v1(scanned_parent_type,edge.parent_id,wide_scopes->scanned_parent_type,\n                            p_rows-used_rows,p_reads-used_reads);\n                        used_rows:=used_rows+(contained->>'rows')::integer;\n                        used_reads:=used_reads+(contained->>'reads')::integer;\n                        bytes:=bytes+(contained->>'bytes')::bigint+octet_length(parent_key)+octet_length((contained->'source')::text)+4;\n                        IF bytes>8388608 THEN RAISE EXCEPTION 'wide parent evidence exceeds byte budget' USING ERRCODE='54000';END IF;\n                        IF contained#>'{source,included}'='true'::jsonb THEN\n                            RAISE EXCEPTION 'nested project mirror and edge lack a native project' USING ERRCODE='40001';\n                        END IF;\n                        inspected:=inspected||jsonb_build_object(parent_key,contained->'source');\n                    END LOOP;",
    "                    IF parent_models ? edge.parent_type THEN\n                        RAISE EXCEPTION 'nested project mirror and edge lack a native project' USING ERRCODE='40001';\n                    END IF;"
  ],
  [
    "parent_models:=parent_models||jsonb_build_object(model,coalesce(parent_models->model,'[]'::jsonb)||jsonb_build_array(scanned_parent_type));",
    "parent_models:=parent_models||jsonb_build_object(model,true);"
  ],
  [
    "        parent_key:=parent_ref::text;\n        contained:=kaname._authority_role_move_parent_containment_v1(parent_ref->>0,parent_ref->>1,\n            parent_scopes->parent_key,p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(contained->>'rows')::integer;\n        used_reads:=used_reads+(contained->>'reads')::integer;\n        bytes:=bytes+(contained->>'bytes')::bigint+octet_length(parent_key)+octet_length((contained->'source')::text)+4;\n        IF bytes>8388608 THEN RAISE EXCEPTION 'parent containment evidence exceeds byte budget' USING ERRCODE='54000';END IF;\n        parent_states:=parent_states||jsonb_build_object(parent_key,contained->'source');\n        IF p_expected IS NOT NULL AND p_expected->'parent_states'->parent_key IS DISTINCT FROM contained->'source' THEN\n            RAISE EXCEPTION 'finite parent containment changed' USING ERRCODE='40001';\n        END IF;\n        IF contained#>'{source,included}' IS DISTINCT FROM 'true'::jsonb THEN CONTINUE;END IF;",
    "        parent_key:=parent_ref::text;"
  ],
  [
    "        finite_parents:=p_expected->'finite_parents';\n        parent_scopes:=p_expected->'parent_scopes';\n        wide_scopes:=p_expected->'wide_scopes';",
    "        finite_parents:=p_expected->'finite_parents';"
  ],
  [
    "WHERE NOT (p_expected->'parent_states' ? (r::text)))\n            OR EXISTS(SELECT FROM jsonb_each(parent_scopes) s CROSS JOIN LATERAL jsonb_array_elements(s.value) v\n                WHERE NOT EXISTS(SELECT FROM jsonb_array_elements(p_expected->'parent_scopes'->s.key) old_scope WHERE old_scope=v))\n            OR EXISTS(SELECT FROM jsonb_each(wide_scopes) s CROSS JOIN LATERAL jsonb_array_elements(s.value) v\n                WHERE NOT EXISTS(SELECT FROM jsonb_array_elements(p_expected->'wide_scopes'->s.key) old_scope WHERE old_scope=v))",
    "WHERE NOT (p_expected->'parent_edges' ? (r::text)))"
  ],
  [
    "    ), grouped AS (SELECT t,jsonb_agg(scope ORDER BY scope) scopes FROM distinct_wide GROUP BY t)\n    SELECT coalesce(jsonb_agg(t ORDER BY t COLLATE \"C\"),'[]'::jsonb),coalesce(jsonb_object_agg(t,scopes),'{}'::jsonb)\n        INTO nested_types,wide_scopes FROM grouped;\n    SELECT nested_types",
    "    ) types;\n    SELECT nested_types"
  ],
  [
    "SELECT DISTINCT (i->>'read_type') COLLATE \"C\" t,i->'scope' scope FROM jsonb_array_elements(p_plan->'items') i",
    "SELECT DISTINCT (i->>'read_type') COLLATE \"C\" t FROM jsonb_array_elements(p_plan->'items') i"
  ],
  [
    "    WITH distinct_wide AS (",
    "    SELECT coalesce(jsonb_agg(t ORDER BY t COLLATE \"C\"),'[]'::jsonb) INTO nested_types FROM ("
  ],
  [
    "        ,coalesce(jsonb_object_agg(jsonb_build_array(typ,id)::text,scope_list),'{}'::jsonb)\n        INTO finite_parents,parent_scopes FROM grouped;",
    "        INTO finite_parents FROM distinct_parents;"
  ],
  [
    "),\n    distinct_parents AS (SELECT DISTINCT typ COLLATE \"C\" typ,id COLLATE \"C\" id,scope FROM parents),\n    grouped AS (SELECT typ,id,jsonb_agg(scope ORDER BY scope) scope_list FROM distinct_parents GROUP BY typ,id)",
    "), distinct_parents AS (SELECT DISTINCT typ COLLATE \"C\" typ,id COLLATE \"C\" id FROM parents)"
  ],
  [
    "SELECT typ,v.id,jsonb_build_array(scope_kind,scope_id) FROM items CROSS",
    "SELECT typ,v.id FROM items CROSS"
  ],
  [
    "SELECT typ,scope_id AS id,jsonb_build_array(scope_kind,scope_id) AS scope FROM items",
    "SELECT typ,scope_id AS id FROM items"
  ],
  [
    "            OR jsonb_typeof(p_expected->'parent_scopes') IS DISTINCT FROM 'object'\n            OR jsonb_typeof(p_expected->'parent_states') IS DISTINCT FROM 'object'\n            OR jsonb_typeof(p_expected->'wide_scopes') IS DISTINCT FROM 'object'\n            OR jsonb_typeof(p_expected->'parent_edges')",
    "            OR jsonb_typeof(p_expected->'parent_edges')"
  ],
  [
    "    finite_parents jsonb;\n    parent_scopes jsonb;\n    parent_states jsonb:='{}'::jsonb;\n    contained jsonb;\n    wide_scopes jsonb;\n    inspected jsonb:='{}'::jsonb;",
    "    finite_parents jsonb;"
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

DROP FUNCTION kaname._authority_role_move_parent_containment_v1(text,text,jsonb,integer,integer);
