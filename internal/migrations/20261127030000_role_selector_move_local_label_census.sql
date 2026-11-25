-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_local_label_candidates_v1(
    p_frozen jsonb,p_plan jsonb,p_commands jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $labels$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    replay boolean:=p_commands IS NOT NULL;
    expected jsonb;source jsonb;sources jsonb:='{}';rel regclass;typ text;
    branch record;ordinal bigint;entry jsonb;r record;images jsonb[];image jsonb;image_bytes bigint;
    cmd jsonb;overlays jsonb;seen integer;needed integer;cap integer;expected_count integer;
    used_rows integer;used_reads integer:=0;output_bytes bigint:=2;reserved_branches boolean:=false;
    predicate jsonb;hits jsonb;invalid_id boolean;item jsonb;items jsonb[]:=ARRAY[]::jsonb[];
BEGIN
    IF p_frozen->'nonce' IS DISTINCT FROM proof->'nonce' OR p_frozen->'invoker_oid' IS DISTINCT FROM proof->'invoker_oid'
        OR p_frozen#>>'{copies,backend_pid}' IS DISTINCT FROM pg_backend_pid()::text
        OR p_frozen#>>'{copies,txid}' IS DISTINCT FROM pg_current_xact_id()::text
        OR coalesce(p_frozen->>'role_id','')='' OR p_frozen#>>'{role,physical,2,id}' IS DISTINCT FROM p_frozen->>'role_id'
        OR p_frozen#>>'{role,new_role,id}' IS DISTINCT FROM p_frozen->>'role_id'
        OR p_plan->'catalog_id' IS DISTINCT FROM proof->'catalog_id' OR jsonb_typeof(p_plan->'items') IS DISTINCT FROM 'array'
        OR (replay AND (jsonb_typeof(p_commands) IS DISTINCT FROM 'array'
            OR jsonb_typeof(p_frozen->'local_label_sources') IS DISTINCT FROM 'object')) THEN
        RAISE EXCEPTION 'local label census requires held role plan' USING ERRCODE='42501';
    END IF;
    used_rows:=jsonb_array_length(p_plan->'items')+coalesce(jsonb_array_length(p_commands),0);
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 0 AND 4096
        OR octet_length(p_frozen::text)>8388608 OR octet_length(p_plan::text)>8388608 OR octet_length(p_commands::text)>8388608 THEN
        RAISE EXCEPTION 'local label census input budget exceeded' USING ERRCODE='54000';
    END IF;
    -- Лишь итоговые команды прошли проверку полномочий на финальных часах.
    -- Предварительный набор копий может содержать истёкшие объекты или ключи.
    SELECT coalesce(jsonb_object_agg(sub.typ,jsonb_build_object('count',sub.n,'commands',sub.commands)),'{}') INTO overlays FROM (
        SELECT c->>'root_type' typ,count(*) n,jsonb_object_agg(c->>'root_id',c) commands FROM jsonb_array_elements(p_commands) c
        WHERE c->>'root_type' IN ('iam.account','iam.project') GROUP BY c->>'root_type'
    ) sub;
    FOR branch IN SELECT i->>'read_type' read_type,array_agg(q.pos ORDER BY q.pos) ordinals,
        (sum(count(*)) OVER ())::integer required_rows
        FROM jsonb_array_elements(p_plan->'items') WITH ORDINALITY q(i,pos)
        WHERE i->>'read_type' IN ('iam.account','iam.project') AND i->>'guard'='whole_type' AND i#>>'{predicate,Arm}' IN ('2','3')
        GROUP BY i->>'read_type' ORDER BY (i->>'read_type') COLLATE "C" LOOP
        typ:=branch.read_type;
        rel:=CASE typ WHEN 'iam.account' THEN 'kaname.accounts'::regclass ELSE 'kaname.projects'::regclass END;
        expected:=p_frozen->'local_label_sources'->typ;
        IF replay AND coalesce(expected->>'state','') NOT IN ('held','pending_budget') THEN
            RAISE EXCEPTION 'local label predicate lacks prepared source' USING ERRCODE='40001';
        END IF;
        -- Обязательные отметки всех типов оплачиваются до первого чтения.
        -- Если дальнейший бюджет исчерпан, возвращаются отметки pending_budget.
        IF NOT reserved_branches THEN
            used_rows:=used_rows+branch.required_rows;
            IF used_rows>p_rows THEN RAISE EXCEPTION 'local label branch budget exceeded' USING ERRCODE='54000';END IF;
            reserved_branches:=true;
        END IF;
        -- Три операции на тип (замок, custody, таблица) и место для контрольной строки.
        cap:=least(4096,p_rows-used_rows-4);
        expected_count:=NULL;
        IF replay AND expected->>'state'='held' THEN
            IF jsonb_typeof(expected->'count') IS DISTINCT FROM 'number' OR expected->>'count' !~ '^(0|[1-9][0-9]{0,3})$'
                OR (expected->>'count')::integer>4096 THEN RAISE EXCEPTION 'local label census count invalid' USING ERRCODE='42501';END IF;
            expected_count:=(expected->>'count')::integer;
            cap:=least(cap,expected_count);
        END IF;
        source:=jsonb_build_object('state','pending_budget');
        images:=ARRAY[]::jsonb[];image_bytes:=2;seen:=0;
        IF cap>=0 AND p_reads-used_reads>=3 AND (NOT replay OR expected->>'state'='held') THEN
            used_rows:=used_rows+3;used_reads:=used_reads+3;
            IF NOT replay THEN
                EXECUTE format('LOCK TABLE ONLY %s IN SHARE MODE NOWAIT',rel);
            END IF;
            IF NOT EXISTS(SELECT FROM pg_locks l JOIN pg_class c ON c.oid=l.relation
                WHERE l.pid=pg_backend_pid() AND l.locktype='relation' AND l.granted AND l.mode='ShareLock'
                AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND c.oid=rel
                AND c.relowner=current_user::regrole AND c.relkind='r' AND c.relpersistence='p'
                AND NOT (c.relispartition OR c.relrowsecurity OR c.relforcerowsecurity OR c.relhasrules)
                AND has_table_privilege((proof->>'invoker_oid')::oid,c.oid,'SELECT')
                AND EXISTS(SELECT FROM pg_index idx JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='id' AND NOT a.attisdropped
                    WHERE idx.indrelid=c.oid AND idx.indisprimary AND idx.indisvalid AND idx.indisready AND idx.indimmediate
                        AND idx.indnkeyatts=1 AND idx.indkey[0]=a.attnum)
                AND NOT EXISTS(SELECT FROM pg_inherits i WHERE i.inhparent=c.oid OR i.inhrelid=c.oid)) THEN
                RAISE EXCEPTION 'local label census lacks physical source guard' USING ERRCODE='42501';
            END IF;
            source:=jsonb_build_object('state','held');
            FOR r IN EXECUTE format('SELECT o.xmin::text x,o.ctid::text t,o.id,o.labels,o.access_labels FROM ONLY %s o LIMIT $1',rel)
                    USING cap+1 LOOP
                used_rows:=used_rows+1;
                IF cardinality(images)>=cap THEN
                    IF cap=expected_count THEN RAISE EXCEPTION 'local label census grew after preparation' USING ERRCODE='40001';END IF;
                    source:=jsonb_build_object('state','pending_budget');EXIT;
                END IF;
                image:=jsonb_build_array(r.x,r.t,r.id,r.labels,r.access_labels);
                image_bytes:=image_bytes+octet_length(image::text)+2;
                IF image_bytes>8388608 OR octet_length(r.id)>16384 THEN source:=jsonb_build_object('state','pending_budget');EXIT;END IF;
                cmd:=overlays->typ->'commands'->r.id;
                IF cmd IS NOT NULL THEN
                    IF cmd#>>'{physical,0}' IS DISTINCT FROM r.x OR cmd#>>'{physical,1}' IS DISTINCT FROM r.t
                        OR cmd#>>'{physical,2,id}' IS DISTINCT FROM r.id OR cmd#>'{physical,2,labels}' IS DISTINCT FROM r.labels
                        OR cmd#>'{physical,2,access_labels}' IS DISTINCT FROM r.access_labels
                        OR kaname.access_labels_valid_v1(cmd->'access_labels') IS DISTINCT FROM true THEN
                        RAISE EXCEPTION 'local label copy differs from census' USING ERRCODE='40001';
                    END IF;
                    seen:=seen+1;
                END IF;
                images:=array_append(images,image);
            END LOOP;
            IF source->>'state'='held' THEN
                needed:=coalesce((overlays->typ->>'count')::integer,0);
                IF seen<>needed THEN RAISE EXCEPTION 'local label copy outside census' USING ERRCODE='40001';END IF;
                SELECT source||jsonb_build_object('count',cardinality(images),'sha256',
                    encode(sha256(convert_to(coalesce(jsonb_agg(v ORDER BY (v->>1)::tid),'[]')::text,'UTF8')),'hex'))
                    INTO source FROM unnest(images) v;
                IF replay AND source IS DISTINCT FROM expected THEN RAISE EXCEPTION 'local label census differs from preparation' USING ERRCODE='40001';END IF;
            END IF;
        END IF;
        sources:=sources||jsonb_build_object(typ,source);
        IF replay THEN
            FOREACH ordinal IN ARRAY branch.ordinals LOOP
                entry:=p_plan->'items'->(ordinal::integer-1);
                item:=jsonb_build_object('plan_item',ordinal,'binding_id',entry->'binding_id',
                    'rule_fp',entry->'rule_fp','side',entry->'side','read_type',typ);
                IF source->>'state'='held' AND cardinality(images)<=p_rows-used_rows THEN
                    used_rows:=used_rows+cardinality(images);
                    predicate:=jsonb_build_object('object_types',jsonb_build_array(typ))||CASE entry#>>'{predicate,Arm}'
                        WHEN '2' THEN jsonb_build_object('arm','labels','match_labels',entry#>'{predicate,MatchLabels}')
                        ELSE jsonb_build_object('arm','access_labels','match_access_labels',entry#>'{predicate,MatchAccessLabels}') END;
                    SELECT coalesce(jsonb_agg(v->2 ORDER BY (v->>2) COLLATE "C"),'[]'),
                        bool_or((v->>2)='' OR (v->>2) ~ '[:#*[:space:][:cntrl:]]') INTO hits,invalid_id FROM unnest(images) v
                        WHERE kaname._authority_resource_selector_matches_v3(predicate,typ,v->>2,v->3,
                            CASE WHEN entry->>'side'='new' THEN coalesce(overlays->typ->'commands'->(v->>2)->'access_labels',v->4) ELSE v->4 END);
                    IF invalid_id THEN
                        RAISE EXCEPTION 'local label candidate id invalid' USING ERRCODE='42501';
                    END IF;
                    item:=item||jsonb_build_object('state','complete','candidate_ids',hits);
                    IF entry ? 'child_predicate' THEN
                        item:=item||jsonb_build_object('children',CASE WHEN hits='[]'::jsonb THEN 'empty' ELSE 'pending' END);
                    END IF;
                ELSE item:=item||jsonb_build_object('state','pending_budget');END IF;
                output_bytes:=output_bytes+octet_length(item::text)+2;
                IF output_bytes>8388608 THEN RAISE EXCEPTION 'local label results exceed byte budget' USING ERRCODE='54000';END IF;
                items:=array_append(items,item);
            END LOOP;
        END IF;
    END LOOP;
    RETURN jsonb_build_object('sources',sources,'items',to_jsonb(items),'other_predicates','pending','rows',used_rows,'reads',used_reads);
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'local label census busy' USING ERRCODE='40001';
END;
$labels$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE grantee record;fn regprocedure:='kaname._authority_role_move_local_label_candidates_v1(jsonb,jsonb,jsonb,integer,integer)'::regprocedure;
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
DO $labels_install$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','e5dd08ae64e954d276d540831ab33f540b0427ddf2ea7e2d2f6c82d1c30cd7e9','21953f6ecf57aab0b3ac8389d838978dd8acf8ba15088d4afe71ae0b1dddd386',$changes$[
 [
  "    binding_labels jsonb;",
  "    binding_labels jsonb;\n    local_labels jsonb;"
 ],
 [
  "'binding_label_source',jsonb_build_object('state','unused')",
  "'binding_label_source',jsonb_build_object('state','unused'),'local_label_sources','{}'::jsonb"
 ],
 [
  "        frozen:=frozen||jsonb_build_object('finite_positions',positions->'positions','binding_label_source',binding_labels->'source');",
  "        local_labels:=kaname._authority_role_move_local_label_candidates_v1(frozen,predicates->'plan',NULL,p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(local_labels->>'rows')::integer;\n        used_reads:=used_reads+(local_labels->>'reads')::integer;\n        frozen:=frozen||jsonb_build_object('finite_positions',positions->'positions','binding_label_source',binding_labels->'source',\n            'local_label_sources',local_labels->'sources');"
 ]
]$changes$::jsonb),
  ('_authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)','4040ee5e25fc3986a261ea16cedcfc2657efb356b9a1729db9df10c1070d8762','8818e245bf1517db88a091c9bbb9b950da510eaa50db01f685a6772e49d68e27',$changes$[
 [
  "    binding_labels jsonb;",
  "    binding_labels jsonb;\n    local_labels jsonb;"
 ],
 [
  "    RETURN jsonb_build_object('role_id',root_id,'actor',actor,'decision_at',at_time,",
  "    local_labels:=kaname._authority_role_move_local_label_candidates_v1(p_frozen,predicates->'plan',result->'commands',p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(local_labels->>'rows')::integer;\n    used_reads:=used_reads+(local_labels->>'reads')::integer;\n    RETURN jsonb_build_object('role_id',root_id,'actor',actor,'decision_at',at_time,\n        'local_label_candidates',local_labels-ARRAY['rows','reads'],"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','c9ca3e5c3dd9ab241d3212dd1fd92fc9a71e1fd924081d26685d6d8d4934f9a8','8c3cc9e8c6f21152ab96d259fdf48d4de6084166f65198efef15428588d8a7ac',$changes$[
 [
  "e5dd08ae64e954d276d540831ab33f540b0427ddf2ea7e2d2f6c82d1c30cd7e9",
  "21953f6ecf57aab0b3ac8389d838978dd8acf8ba15088d4afe71ae0b1dddd386"
 ],
 [
  "4040ee5e25fc3986a261ea16cedcfc2657efb356b9a1729db9df10c1070d8762",
  "8818e245bf1517db88a091c9bbb9b950da510eaa50db01f685a6772e49d68e27"
 ],
 [
  " ('_authority_role_move_binding_label_candidates_v1(jsonb,jsonb,boolean,integer,integer)','1e54b2d219066b958e4973f98f93e50dc03e6fb520c23e45428a2c55a302f057',false,'v',true,'private'),",
  " ('_authority_role_move_binding_label_candidates_v1(jsonb,jsonb,boolean,integer,integer)','1e54b2d219066b958e4973f98f93e50dc03e6fb520c23e45428a2c55a302f057',false,'v',true,'private'),\n ('_authority_role_move_local_label_candidates_v1(jsonb,jsonb,jsonb,integer,integer)','ff793372e4386bfdbf9e8b9e8e8431c0a1046972339261787e9fb53fe73fc4b0',false,'v',true,'private'),"
 ],
 [
  "  ('_authority_role_move_binding_label_candidates_v1(jsonb,jsonb,boolean,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_replay','p_rows','p_reads']),",
  "  ('_authority_role_move_binding_label_candidates_v1(jsonb,jsonb,boolean,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_replay','p_rows','p_reads']),\n  ('_authority_role_move_local_label_candidates_v1(jsonb,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_commands','p_rows','p_reads']),"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','e984071291b9298c9b64feb16d18595bc29f543dc47db64e0606eab07cf27394','118dc9d4b0a043157b35dd37052c88b6f15e5df0c6ec02b9ff064fbd97d4e63c',$changes$[
 [
  "c9ca3e5c3dd9ab241d3212dd1fd92fc9a71e1fd924081d26685d6d8d4934f9a8",
  "8c3cc9e8c6f21152ab96d259fdf48d4de6084166f65198efef15428588d8a7ac"
 ]
]$changes$::jsonb),
  ('authority_metadata_service_account_access_label_ready_v1()','b05aa0f76adb3f06c3fa14f319853f66c2768c3abd2d0608baab07b0bf9b5473','4c2d792d1541847ebd71c7e1c08b70193ac3babe6967e4beb438a6b5fc7566da',$changes$[
 [
  "c9ca3e5c3dd9ab241d3212dd1fd92fc9a71e1fd924081d26685d6d8d4934f9a8",
  "8c3cc9e8c6f21152ab96d259fdf48d4de6084166f65198efef15428588d8a7ac"
 ],
 [
  "e984071291b9298c9b64feb16d18595bc29f543dc47db64e0606eab07cf27394",
  "118dc9d4b0a043157b35dd37052c88b6f15e5df0c6ec02b9ff064fbd97d4e63c"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move local label census predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move local label census splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move local label census body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move local label census function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move local label census function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move local label census custody differs after migration' USING ERRCODE='55000';END IF;
END;
$labels_install$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $labels_install$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('authority_metadata_service_account_access_label_ready_v1()','4c2d792d1541847ebd71c7e1c08b70193ac3babe6967e4beb438a6b5fc7566da','b05aa0f76adb3f06c3fa14f319853f66c2768c3abd2d0608baab07b0bf9b5473',$changes$[
 [
  "118dc9d4b0a043157b35dd37052c88b6f15e5df0c6ec02b9ff064fbd97d4e63c",
  "e984071291b9298c9b64feb16d18595bc29f543dc47db64e0606eab07cf27394"
 ],
 [
  "8c3cc9e8c6f21152ab96d259fdf48d4de6084166f65198efef15428588d8a7ac",
  "c9ca3e5c3dd9ab241d3212dd1fd92fc9a71e1fd924081d26685d6d8d4934f9a8"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','118dc9d4b0a043157b35dd37052c88b6f15e5df0c6ec02b9ff064fbd97d4e63c','e984071291b9298c9b64feb16d18595bc29f543dc47db64e0606eab07cf27394',$changes$[
 [
  "8c3cc9e8c6f21152ab96d259fdf48d4de6084166f65198efef15428588d8a7ac",
  "c9ca3e5c3dd9ab241d3212dd1fd92fc9a71e1fd924081d26685d6d8d4934f9a8"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','8c3cc9e8c6f21152ab96d259fdf48d4de6084166f65198efef15428588d8a7ac','c9ca3e5c3dd9ab241d3212dd1fd92fc9a71e1fd924081d26685d6d8d4934f9a8',$changes$[
 [
  "  ('_authority_role_move_binding_label_candidates_v1(jsonb,jsonb,boolean,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_replay','p_rows','p_reads']),\n  ('_authority_role_move_local_label_candidates_v1(jsonb,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_commands','p_rows','p_reads']),",
  "  ('_authority_role_move_binding_label_candidates_v1(jsonb,jsonb,boolean,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_replay','p_rows','p_reads']),"
 ],
 [
  " ('_authority_role_move_binding_label_candidates_v1(jsonb,jsonb,boolean,integer,integer)','1e54b2d219066b958e4973f98f93e50dc03e6fb520c23e45428a2c55a302f057',false,'v',true,'private'),\n ('_authority_role_move_local_label_candidates_v1(jsonb,jsonb,jsonb,integer,integer)','ff793372e4386bfdbf9e8b9e8e8431c0a1046972339261787e9fb53fe73fc4b0',false,'v',true,'private'),",
  " ('_authority_role_move_binding_label_candidates_v1(jsonb,jsonb,boolean,integer,integer)','1e54b2d219066b958e4973f98f93e50dc03e6fb520c23e45428a2c55a302f057',false,'v',true,'private'),"
 ],
 [
  "8818e245bf1517db88a091c9bbb9b950da510eaa50db01f685a6772e49d68e27",
  "4040ee5e25fc3986a261ea16cedcfc2657efb356b9a1729db9df10c1070d8762"
 ],
 [
  "21953f6ecf57aab0b3ac8389d838978dd8acf8ba15088d4afe71ae0b1dddd386",
  "e5dd08ae64e954d276d540831ab33f540b0427ddf2ea7e2d2f6c82d1c30cd7e9"
 ]
]$changes$::jsonb),
  ('_authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)','8818e245bf1517db88a091c9bbb9b950da510eaa50db01f685a6772e49d68e27','4040ee5e25fc3986a261ea16cedcfc2657efb356b9a1729db9df10c1070d8762',$changes$[
 [
  "    local_labels:=kaname._authority_role_move_local_label_candidates_v1(p_frozen,predicates->'plan',result->'commands',p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(local_labels->>'rows')::integer;\n    used_reads:=used_reads+(local_labels->>'reads')::integer;\n    RETURN jsonb_build_object('role_id',root_id,'actor',actor,'decision_at',at_time,\n        'local_label_candidates',local_labels-ARRAY['rows','reads'],",
  "    RETURN jsonb_build_object('role_id',root_id,'actor',actor,'decision_at',at_time,"
 ],
 [
  "    binding_labels jsonb;\n    local_labels jsonb;",
  "    binding_labels jsonb;"
 ]
]$changes$::jsonb),
  ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','21953f6ecf57aab0b3ac8389d838978dd8acf8ba15088d4afe71ae0b1dddd386','e5dd08ae64e954d276d540831ab33f540b0427ddf2ea7e2d2f6c82d1c30cd7e9',$changes$[
 [
  "        local_labels:=kaname._authority_role_move_local_label_candidates_v1(frozen,predicates->'plan',NULL,p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(local_labels->>'rows')::integer;\n        used_reads:=used_reads+(local_labels->>'reads')::integer;\n        frozen:=frozen||jsonb_build_object('finite_positions',positions->'positions','binding_label_source',binding_labels->'source',\n            'local_label_sources',local_labels->'sources');",
  "        frozen:=frozen||jsonb_build_object('finite_positions',positions->'positions','binding_label_source',binding_labels->'source');"
 ],
 [
  "'binding_label_source',jsonb_build_object('state','unused'),'local_label_sources','{}'::jsonb",
  "'binding_label_source',jsonb_build_object('state','unused')"
 ],
 [
  "    binding_labels jsonb;\n    local_labels jsonb;",
  "    binding_labels jsonb;"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move local label census predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move local label census splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move local label census body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move local label census function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move local label census function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move local label census custody differs after migration' USING ERRCODE='55000';END IF;
END;
$labels_install$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_role_move_local_label_candidates_v1(jsonb,jsonb,jsonb,integer,integer);
