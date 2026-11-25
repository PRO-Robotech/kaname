-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_raw_project_children_v1(
    p_frozen jsonb,p_plan jsonb,p_replay boolean,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $graph$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    expected jsonb:=p_frozen->'raw_project_children';
    source jsonb:=jsonb_build_object('state','pending_budget');
    scope_ids text[];scope_id text;parent_model text;child_model text;
    oversized boolean;versions jsonb;images jsonb[]:=ARRAY[]::jsonb[];image jsonb;matched jsonb;
    r record;raw_edges refcursor;mirror_version jsonb;expected_count integer;cap integer;seen integer:=0;used_rows integer:=0;used_reads integer:=0;
    image_bytes bigint:=2;
BEGIN
    IF p_replay IS NULL OR p_frozen->'nonce' IS DISTINCT FROM proof->'nonce'
        OR p_frozen->'invoker_oid' IS DISTINCT FROM proof->'invoker_oid'
        OR p_frozen#>>'{copies,backend_pid}' IS DISTINCT FROM pg_backend_pid()::text
        OR p_frozen#>>'{copies,txid}' IS DISTINCT FROM pg_current_xact_id()::text
        OR p_plan->'catalog_id' IS DISTINCT FROM proof->'catalog_id'
        OR jsonb_typeof(p_plan->'items') IS DISTINCT FROM 'array'
        OR (p_replay AND jsonb_typeof(expected) IS DISTINCT FROM 'object') THEN
        RAISE EXCEPTION 'raw project children require a held role plan' USING ERRCODE='42501';
    END IF;
    IF p_replay THEN
        CASE expected->>'state'
            WHEN 'held' THEN
                IF expected-ARRAY['state','scope_id','catalog','count','sha256']<>'{}'::jsonb
                    OR jsonb_typeof(expected->'scope_id') IS DISTINCT FROM 'string' OR coalesce(expected->>'scope_id','')=''
                    OR jsonb_typeof(expected->'catalog') IS DISTINCT FROM 'array'
                    OR jsonb_typeof(expected->'count') IS DISTINCT FROM 'number'
                    OR expected->>'count' !~ '^(0|[1-9][0-9]{0,3})$'
                    OR jsonb_typeof(expected->'sha256') IS DISTINCT FROM 'string'
                    OR expected->>'sha256' !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'invalid held project child source' USING ERRCODE='42501';
                END IF;
                expected_count:=(expected->>'count')::integer;
                IF expected_count>4096 OR jsonb_array_length(expected->'catalog')>2 THEN
                    RAISE EXCEPTION 'invalid held project child count' USING ERRCODE='42501';
                END IF;
            WHEN 'unused','pending_budget','pending_scopes' THEN
                IF expected IS DISTINCT FROM jsonb_build_object('state',expected->'state') THEN
                    RAISE EXCEPTION 'invalid pending project child source' USING ERRCODE='42501';
                END IF;
            ELSE RAISE EXCEPTION 'unknown prepared project child source' USING ERRCODE='42501';
        END CASE;
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 0 AND 4096 THEN
        RAISE EXCEPTION 'invalid project children budget' USING ERRCODE='54000';
    END IF;
    IF jsonb_array_length(p_plan->'items')<=p_rows THEN
        used_rows:=jsonb_array_length(p_plan->'items');
        SELECT array_agg(DISTINCT (i#>>'{scope,1}') COLLATE "C") INTO scope_ids
        FROM jsonb_array_elements(p_plan->'items') i
        WHERE i->>'guard'='whole_type' AND i->>'read_type'='iam.account' AND i->>'child_type'='iam.project'
            AND i#>>'{predicate,Arm}' IN ('2','3') AND i#>>'{scope,0}'='account' AND i->'target_ids'='[]';
        IF scope_ids IS NULL THEN source:=jsonb_build_object('state','unused');
        ELSIF cardinality(scope_ids)>1 THEN source:=jsonb_build_object('state','pending_scopes');
        ELSE scope_id:=scope_ids[1];END IF;
    END IF;
    IF p_replay AND ((scope_id IS NOT NULL AND (expected->>'state'='unused'
            OR (expected_count IS NOT NULL AND scope_id IS DISTINCT FROM expected->>'scope_id')))
        OR (source->>'state'='pending_scopes' AND expected->>'state' IN ('held','unused'))) THEN
        RAISE EXCEPTION 'project child scopes changed' USING ERRCODE='40001';
    END IF;
    IF scope_id IS NOT NULL AND coalesce(scope_id,'')<>'' AND p_rows-used_rows>=13 AND p_reads>=12
        AND (NOT p_replay OR expected->>'state'='held') THEN
        IF NOT p_replay THEN
            -- Тот же порядок, что у регистрации и снятия: зеркало перед рёбрами.
            LOCK TABLE ONLY kaname.catalog_resource, ONLY kaname.resource_mirror, ONLY kaname.resource_parent_edge
                IN SHARE MODE NOWAIT;
        END IF;
        used_reads:=11;used_rows:=used_rows+10;
        IF EXISTS(SELECT FROM unnest(ARRAY['kaname.catalog_resource'::regclass,'kaname.resource_mirror'::regclass,
                    'kaname.resource_parent_edge'::regclass]) relation(oid)
            WHERE NOT EXISTS(SELECT FROM pg_class c JOIN pg_locks l ON l.relation=c.oid WHERE c.oid=relation.oid
                AND c.relowner=current_user::regrole AND c.relkind='r' AND c.relpersistence='p'
                AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relispartition OR c.relhasrules)
                AND NOT EXISTS(SELECT FROM pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid)
                AND has_table_privilege((proof->>'invoker_oid')::oid,c.oid,'SELECT')
                AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
                AND l.pid=pg_backend_pid() AND l.granted AND l.locktype='relation' AND l.mode='ShareLock')) THEN
            RAISE EXCEPTION 'project children source custody differs' USING ERRCODE='42501';
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
            RAISE EXCEPTION 'project children source keys differ' USING ERRCODE='42501';
        END IF;
        SELECT coalesce(jsonb_agg(jsonb_build_array(c.dotted,c.object_type,c.x,c.t) ORDER BY c.dotted COLLATE "C"),'[]'),
            max(c.object_type) FILTER(WHERE c.dotted='iam.account'),max(c.object_type) FILTER(WHERE c.dotted='iam.project'),bool_or(c.too_long)
            INTO versions,parent_model,child_model,oversized
        FROM (SELECT c.dotted,CASE WHEN octet_length(c.object_type)<=16384 THEN c.object_type END AS object_type,
                octet_length(c.object_type)>16384 AS too_long,c.xmin::text x,c.ctid::text t FROM ONLY kaname.catalog_resource c
            WHERE c.live AND c.dotted IN ('iam.account','iam.project') LIMIT 3) c;
        used_rows:=used_rows+jsonb_array_length(versions);
        IF oversized THEN RAISE EXCEPTION 'oversized project child catalog identity' USING ERRCODE='54000';END IF;
        IF jsonb_array_length(versions)>2 OR (jsonb_array_length(versions)=2 AND (parent_model IS NULL OR child_model IS NULL)) THEN
            RAISE EXCEPTION 'ambiguous project child catalog' USING ERRCODE='42501';
        END IF;
        cap:=least(4096,(p_rows-used_rows-1)/4,(p_reads-used_reads-1)/2);
        IF expected_count IS NOT NULL THEN cap:=least(cap,expected_count);END IF;
        source:=jsonb_build_object('state','held','scope_id',scope_id,'catalog',versions);
        IF parent_model IS NOT NULL AND child_model IS NOT NULL THEN
            -- Сначала ограничиваем все физические рёбра одного родителя, включая сирот и другие типы.
            -- Для подходящего ребёнка точечный поиск зеркала имеет не более одного результата по PK.
            -- Явный FETCH по одной строке. PL/pgSQL FOR по запросу предвыбирает пачку;
            -- контрольная строка и слишком длинные ключи не запускают чтение зеркала.
            OPEN raw_edges NO SCROLL FOR
                SELECT pe.xmin::text AS x,pe.ctid::text AS t,
                    CASE WHEN octet_length(pe.object_id)<=16384 THEN pe.object_id END AS object_id,
                    CASE WHEN octet_length(pe.object_type)<=16384 THEN pe.object_type END AS object_type
                FROM ONLY kaname.resource_parent_edge pe
                WHERE pe.parent_type=parent_model AND pe.parent_id=scope_id LIMIT cap+1;
            LOOP
                FETCH NEXT FROM raw_edges INTO r;
                used_reads:=used_reads+1;
                EXIT WHEN NOT FOUND;
                seen:=seen+1;used_rows:=used_rows+1;
                IF seen>cap THEN
                    IF cap=expected_count THEN
                        RAISE EXCEPTION 'project child census grew after preparation' USING ERRCODE='40001';
                    END IF;
                    source:=jsonb_build_object('state','pending_budget');EXIT;
                END IF;
                IF r.object_id IS NULL OR r.object_type IS NULL THEN
                    IF p_replay THEN RAISE EXCEPTION 'project child keys changed' USING ERRCODE='40001';END IF;
                    source:=jsonb_build_object('state','pending_budget');EXIT;
                END IF;
                mirror_version:=NULL;
                IF r.object_type=child_model THEN
                    used_reads:=used_reads+1;used_rows:=used_rows+1;
                    SELECT jsonb_build_array(m.xmin::text,m.ctid::text) INTO mirror_version FROM ONLY kaname.resource_mirror m
                    WHERE m.object_type='iam.project' AND m.object_id=r.object_id;
                END IF;
                used_rows:=used_rows+2;
                IF mirror_version IS NOT NULL AND (r.object_id='' OR r.object_id ~ '[:#*[:space:][:cntrl:]]') THEN
                    RAISE EXCEPTION 'invalid project child identity' USING ERRCODE='42501';
                END IF;
                image:=jsonb_build_array(r.x,r.t,r.object_type,r.object_id,mirror_version);
                image_bytes:=image_bytes+octet_length(image::text)+2;
                IF image_bytes>8388608 THEN
                    IF p_replay THEN RAISE EXCEPTION 'project child images grew after preparation' USING ERRCODE='40001';END IF;
                    source:=jsonb_build_object('state','pending_budget');EXIT;
                END IF;
                images:=array_append(images,image);
            END LOOP;
            CLOSE raw_edges;
        END IF;
        IF source->>'state'='held' THEN
            SELECT source||jsonb_build_object('count',cardinality(images),'sha256',
                encode(sha256(convert_to(coalesce(jsonb_agg(v ORDER BY (v->>1)::tid),'[]')::text,'UTF8')),'hex'))
                INTO source FROM unnest(images) v;
            IF p_replay THEN
                SELECT coalesce(jsonb_agg(id ORDER BY id COLLATE "C"),'[]') INTO matched
                FROM (SELECT DISTINCT (v->>3) COLLATE "C" AS id FROM unnest(images) v WHERE v->4<>'null'::jsonb) ids;
            END IF;
        END IF;
        IF p_replay AND source->>'state'='held' AND source IS DISTINCT FROM expected THEN
            RAISE EXCEPTION 'project child census changed' USING ERRCODE='40001';
        END IF;
    END IF;
    RETURN jsonb_build_object('source',source,'candidate_ids',matched,'rows',used_rows,'reads',used_reads);
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'project child sources busy' USING ERRCODE='40001';
END;
$graph$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE grantee record;fn regprocedure:='kaname._authority_role_move_raw_project_children_v1(jsonb,jsonb,boolean,integer,integer)'::regprocedure;
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
DO $scope_install$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('_authority_role_move_local_label_candidates_v1(jsonb,jsonb,jsonb,integer,integer)','1c3c9eea115f6370d6776ec0d18fdfd22f612db49e78b5f4af9f8050d1231fc5','f74cc85083a9e31d4766b5d73de1c9669536cc8b62b80d5609eebec55546bda2',$changes$[
 [
  "scope_id_hit boolean;item",
  "scope_id_hit boolean;graph jsonb;n integer;item"
 ],
 [
  "    RETURN jsonb_build_object('sources',sources,'items',to_jsonb(items),'other_predicates','pending','rows',used_rows,'reads',used_reads);",
  "    graph:=kaname._authority_role_move_raw_project_children_v1(p_frozen,p_plan,replay,p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(graph->>'rows')::integer;used_reads:=used_reads+(graph->>'reads')::integer;\n    IF replay AND graph#>>'{source,state}'='held' AND cardinality(items)<=p_rows-used_rows THEN\n        used_rows:=used_rows+cardinality(items);\n        FOR n IN 1..cardinality(items) LOOP\n            item:=items[n];\n            IF item->>'children' IS DISTINCT FROM 'pending' THEN CONTINUE;END IF;\n            entry:=p_plan->'items'->((item->>'plan_item')::integer-1);\n            IF entry->>'read_type'='iam.account' AND entry->>'child_type'='iam.project'\n                AND entry#>>'{scope,0}'='account' AND entry#>>'{scope,1}'=graph#>>'{source,scope_id}'\n                AND entry->>'guard'='whole_type' AND entry->'target_ids'='[]'::jsonb\n                AND jsonb_array_length(graph->'candidate_ids')<=p_rows-used_rows THEN\n                used_rows:=used_rows+jsonb_array_length(graph->'candidate_ids');\n                -- Даже непустой нативный список не подтверждает предков для IAM-direct compiler.\n                image:=jsonb_build_object('raw_child_candidate_ids',graph->'candidate_ids');\n                output_bytes:=output_bytes+octet_length(image::text)+2;\n                IF output_bytes>8388608 THEN RAISE EXCEPTION 'project child results exceed byte budget' USING ERRCODE='54000';END IF;\n                items[n]:=item||image;\n            END IF;\n        END LOOP;\n    END IF;\n    RETURN jsonb_build_object('sources',sources,'raw_project_children',graph->'source','items',to_jsonb(items),\n        'other_predicates','pending','rows',used_rows,'reads',used_reads);"
 ]
]$changes$::jsonb),
  ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','21953f6ecf57aab0b3ac8389d838978dd8acf8ba15088d4afe71ae0b1dddd386','8fe4c3a1e587d9f09db5bd5e7a73df6795166457f57badf53087e1dd0107dd62',$changes$[
 [
  "'local_label_sources','{}'::jsonb",
  "'local_label_sources','{}'::jsonb,'raw_project_children',jsonb_build_object('state','unused')"
 ],
 [
  "'local_label_sources',local_labels->'sources'",
  "'local_label_sources',local_labels->'sources','raw_project_children',local_labels->'raw_project_children'"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','55eed41ac17fb4d8a2df9441a5dbe684ff2d222dab7c5da9da8c3d06a45133fc','4b7124a3872cf53dec09e2b231bf34074e0c577cc96f1e8e5402a04e0613b1f9',$changes$[
 [
  " ('_authority_role_move_local_label_candidates_v1(jsonb,jsonb,jsonb,integer,integer)','1c3c9eea115f6370d6776ec0d18fdfd22f612db49e78b5f4af9f8050d1231fc5',false,'v',true,'private'),",
  " ('_authority_role_move_local_label_candidates_v1(jsonb,jsonb,jsonb,integer,integer)','f74cc85083a9e31d4766b5d73de1c9669536cc8b62b80d5609eebec55546bda2',false,'v',true,'private'),\n ('_authority_role_move_raw_project_children_v1(jsonb,jsonb,boolean,integer,integer)','dfa33dbe61346f9c9504517b11728901a3b034c05cac44f345351ab0dc254983',false,'v',true,'private'),"
 ],
 [
  "  ('_authority_role_move_local_label_candidates_v1(jsonb,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_commands','p_rows','p_reads']),",
  "  ('_authority_role_move_local_label_candidates_v1(jsonb,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_commands','p_rows','p_reads']),\n  ('_authority_role_move_raw_project_children_v1(jsonb,jsonb,boolean,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_replay','p_rows','p_reads']),"
 ],
 [
  "21953f6ecf57aab0b3ac8389d838978dd8acf8ba15088d4afe71ae0b1dddd386",
  "8fe4c3a1e587d9f09db5bd5e7a73df6795166457f57badf53087e1dd0107dd62"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','92d0154becb27b062a829705d047554f6e70d057f7e53a20721c7d69070f4233','e2563ecb2fc5a6cc6df92070cae7f37c55233c34dde064a185e5d8d021b58c76',$changes$[
 [
  "55eed41ac17fb4d8a2df9441a5dbe684ff2d222dab7c5da9da8c3d06a45133fc",
  "4b7124a3872cf53dec09e2b231bf34074e0c577cc96f1e8e5402a04e0613b1f9"
 ]
]$changes$::jsonb),
  ('authority_metadata_service_account_access_label_ready_v1()','3a73fb6d18fa0d9435e9a2dcdf9fb57baa1fbb5eee213eb2cee28b1adf6f25b7','6eb2f8f8356dcbd1fbd9646806062a4f827f332bcf1a394380cb930d875cae18',$changes$[
 [
  "55eed41ac17fb4d8a2df9441a5dbe684ff2d222dab7c5da9da8c3d06a45133fc",
  "4b7124a3872cf53dec09e2b231bf34074e0c577cc96f1e8e5402a04e0613b1f9"
 ],
 [
  "92d0154becb27b062a829705d047554f6e70d057f7e53a20721c7d69070f4233",
  "e2563ecb2fc5a6cc6df92070cae7f37c55233c34dde064a185e5d8d021b58c76"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move raw project descendants predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move raw project descendants splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move raw project descendants body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move raw project descendants function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move raw project descendants function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move raw project descendants custody differs after migration' USING ERRCODE='55000';END IF;
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
  ('authority_metadata_service_account_access_label_ready_v1()','6eb2f8f8356dcbd1fbd9646806062a4f827f332bcf1a394380cb930d875cae18','3a73fb6d18fa0d9435e9a2dcdf9fb57baa1fbb5eee213eb2cee28b1adf6f25b7',$changes$[
 [
  "e2563ecb2fc5a6cc6df92070cae7f37c55233c34dde064a185e5d8d021b58c76",
  "92d0154becb27b062a829705d047554f6e70d057f7e53a20721c7d69070f4233"
 ],
 [
  "4b7124a3872cf53dec09e2b231bf34074e0c577cc96f1e8e5402a04e0613b1f9",
  "55eed41ac17fb4d8a2df9441a5dbe684ff2d222dab7c5da9da8c3d06a45133fc"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','e2563ecb2fc5a6cc6df92070cae7f37c55233c34dde064a185e5d8d021b58c76','92d0154becb27b062a829705d047554f6e70d057f7e53a20721c7d69070f4233',$changes$[
 [
  "4b7124a3872cf53dec09e2b231bf34074e0c577cc96f1e8e5402a04e0613b1f9",
  "55eed41ac17fb4d8a2df9441a5dbe684ff2d222dab7c5da9da8c3d06a45133fc"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','4b7124a3872cf53dec09e2b231bf34074e0c577cc96f1e8e5402a04e0613b1f9','55eed41ac17fb4d8a2df9441a5dbe684ff2d222dab7c5da9da8c3d06a45133fc',$changes$[
 [
  "8fe4c3a1e587d9f09db5bd5e7a73df6795166457f57badf53087e1dd0107dd62",
  "21953f6ecf57aab0b3ac8389d838978dd8acf8ba15088d4afe71ae0b1dddd386"
 ],
 [
  "  ('_authority_role_move_local_label_candidates_v1(jsonb,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_commands','p_rows','p_reads']),\n  ('_authority_role_move_raw_project_children_v1(jsonb,jsonb,boolean,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_replay','p_rows','p_reads']),",
  "  ('_authority_role_move_local_label_candidates_v1(jsonb,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_commands','p_rows','p_reads']),"
 ],
 [
  " ('_authority_role_move_local_label_candidates_v1(jsonb,jsonb,jsonb,integer,integer)','f74cc85083a9e31d4766b5d73de1c9669536cc8b62b80d5609eebec55546bda2',false,'v',true,'private'),\n ('_authority_role_move_raw_project_children_v1(jsonb,jsonb,boolean,integer,integer)','dfa33dbe61346f9c9504517b11728901a3b034c05cac44f345351ab0dc254983',false,'v',true,'private'),",
  " ('_authority_role_move_local_label_candidates_v1(jsonb,jsonb,jsonb,integer,integer)','1c3c9eea115f6370d6776ec0d18fdfd22f612db49e78b5f4af9f8050d1231fc5',false,'v',true,'private'),"
 ]
]$changes$::jsonb),
  ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','8fe4c3a1e587d9f09db5bd5e7a73df6795166457f57badf53087e1dd0107dd62','21953f6ecf57aab0b3ac8389d838978dd8acf8ba15088d4afe71ae0b1dddd386',$changes$[
 [
  "'local_label_sources',local_labels->'sources','raw_project_children',local_labels->'raw_project_children'",
  "'local_label_sources',local_labels->'sources'"
 ],
 [
  "'local_label_sources','{}'::jsonb,'raw_project_children',jsonb_build_object('state','unused')",
  "'local_label_sources','{}'::jsonb"
 ]
]$changes$::jsonb),
  ('_authority_role_move_local_label_candidates_v1(jsonb,jsonb,jsonb,integer,integer)','f74cc85083a9e31d4766b5d73de1c9669536cc8b62b80d5609eebec55546bda2','1c3c9eea115f6370d6776ec0d18fdfd22f612db49e78b5f4af9f8050d1231fc5',$changes$[
 [
  "    graph:=kaname._authority_role_move_raw_project_children_v1(p_frozen,p_plan,replay,p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(graph->>'rows')::integer;used_reads:=used_reads+(graph->>'reads')::integer;\n    IF replay AND graph#>>'{source,state}'='held' AND cardinality(items)<=p_rows-used_rows THEN\n        used_rows:=used_rows+cardinality(items);\n        FOR n IN 1..cardinality(items) LOOP\n            item:=items[n];\n            IF item->>'children' IS DISTINCT FROM 'pending' THEN CONTINUE;END IF;\n            entry:=p_plan->'items'->((item->>'plan_item')::integer-1);\n            IF entry->>'read_type'='iam.account' AND entry->>'child_type'='iam.project'\n                AND entry#>>'{scope,0}'='account' AND entry#>>'{scope,1}'=graph#>>'{source,scope_id}'\n                AND entry->>'guard'='whole_type' AND entry->'target_ids'='[]'::jsonb\n                AND jsonb_array_length(graph->'candidate_ids')<=p_rows-used_rows THEN\n                used_rows:=used_rows+jsonb_array_length(graph->'candidate_ids');\n                -- Даже непустой нативный список не подтверждает предков для IAM-direct compiler.\n                image:=jsonb_build_object('raw_child_candidate_ids',graph->'candidate_ids');\n                output_bytes:=output_bytes+octet_length(image::text)+2;\n                IF output_bytes>8388608 THEN RAISE EXCEPTION 'project child results exceed byte budget' USING ERRCODE='54000';END IF;\n                items[n]:=item||image;\n            END IF;\n        END LOOP;\n    END IF;\n    RETURN jsonb_build_object('sources',sources,'raw_project_children',graph->'source','items',to_jsonb(items),\n        'other_predicates','pending','rows',used_rows,'reads',used_reads);",
  "    RETURN jsonb_build_object('sources',sources,'items',to_jsonb(items),'other_predicates','pending','rows',used_rows,'reads',used_reads);"
 ],
 [
  "scope_id_hit boolean;graph jsonb;n integer;item",
  "scope_id_hit boolean;item"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move raw project descendants predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move raw project descendants splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move raw project descendants body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move raw project descendants function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move raw project descendants function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move raw project descendants custody differs after migration' USING ERRCODE='55000';END IF;
END;
$scope_install$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_role_move_raw_project_children_v1(jsonb,jsonb,boolean,integer,integer);
