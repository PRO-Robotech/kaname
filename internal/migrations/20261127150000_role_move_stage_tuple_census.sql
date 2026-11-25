-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Перепись spool выполняется только на соединении зачисленного LOGIN.
-- До запроса к его pg_temp проверяем обычную heap-таблицу, встроенные типы
-- и единственный стандартный первичный ключ, созданные ролевым RR-writer.
CREATE FUNCTION kaname._authority_role_move_stage_tuple_census_v1(p_retier boolean,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $census$
DECLARE
    proof jsonb;
    spool_oid oid;
    spool_kind "char";
    owner_read boolean;
    tuple_count integer;
    tuple_bytes bigint;
    counts jsonb;
    used_rows constant integer:=1;
BEGIN
    IF p_retier IS NULL OR p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN 2 AND 4096 THEN
        RAISE EXCEPTION 'selector move stage budget absent' USING ERRCODE='54000';
    END IF;
    proof:=kaname._authority_role_move_attestation_v1();
    SELECT c.oid,c.relkind,(SELECT count(*)=1 AND bool_and(a.grantee=current_user::regrole AND a.grantor=c.relowner
            AND a.privilege_type='SELECT' AND NOT a.is_grantable)
        FROM aclexplode(c.relacl) a WHERE a.grantee<>c.relowner)
        INTO spool_oid,spool_kind,owner_read FROM pg_catalog.pg_class c
        WHERE c.relnamespace=pg_my_temp_schema() AND c.relname='kaname_role_stage_tuples';
    IF spool_oid IS NULL THEN
        IF p_retier THEN
            RAISE EXCEPTION 'selector move tuple stage absent' USING ERRCODE='P1034';
        END IF;
        RETURN jsonb_build_object('rows',used_rows,'reads',2,'tuples',0,'counts','{}'::jsonb);
    END IF;
    IF spool_kind<>'r' THEN RAISE EXCEPTION 'selector move tuple stage is not a table' USING ERRCODE='P1034';END IF;
    IF p_reads<5 THEN RAISE EXCEPTION 'selector move stage census budget' USING ERRCODE='54000';END IF;
    IF owner_read IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selector move tuple stage lacks exact owner read grant' USING ERRCODE='42501';
    END IF;
    LOCK TABLE ONLY pg_temp.kaname_role_stage_tuples IN ACCESS SHARE MODE NOWAIT;
    IF NOT EXISTS (
        SELECT FROM pg_catalog.pg_class c
        WHERE c.oid=spool_oid AND c.relname='kaname_role_stage_tuples' AND c.relnamespace=pg_my_temp_schema()
            AND c.relowner=(proof->>'invoker_oid')::oid
            AND c.relkind='r' AND c.relpersistence='t' AND c.relam=(SELECT oid FROM pg_catalog.pg_am WHERE amname='heap')
            AND c.relnatts=5 AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relhassubclass
                OR c.relispartition OR c.relhasrules OR c.relhastriggers)
            AND NOT EXISTS (SELECT FROM pg_catalog.pg_inherits h WHERE h.inhrelid=c.oid OR h.inhparent=c.oid)
            AND NOT EXISTS (SELECT FROM pg_catalog.pg_statistic_ext s WHERE s.stxrelid=c.oid)
            AND NOT EXISTS (SELECT FROM pg_catalog.pg_policy p WHERE p.polrelid=c.oid)
            AND (SELECT array_agg(a.attname::text ORDER BY a.attnum) FROM pg_catalog.pg_attribute a
                WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND a.attnotnull
                    AND a.atttypid='pg_catalog.text'::regtype AND a.atttypmod=-1
                    AND a.attcollation='pg_catalog."default"'::regcollation AND a.attidentity='' AND a.attgenerated=''
                    AND a.attacl IS NULL AND NOT a.atthasdef AND NOT a.atthasmissing AND a.attinhcount=0)
                =ARRAY['binding_id','side','object','fga_user','relation']
            AND NOT EXISTS (SELECT FROM pg_catalog.pg_constraint k WHERE k.conrelid=c.oid OFFSET 1)
            AND NOT EXISTS (SELECT FROM pg_catalog.pg_index i WHERE i.indrelid=c.oid OFFSET 1)
            AND EXISTS (SELECT FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class ix ON ix.oid=i.indexrelid
                JOIN pg_catalog.pg_constraint k ON k.conrelid=c.oid AND k.conindid=ix.oid
                WHERE i.indrelid=c.oid AND k.contype='p' AND k.convalidated AND NOT k.condeferrable
                    AND ix.relkind='i' AND ix.relam=(SELECT oid FROM pg_catalog.pg_am WHERE amname='btree')
                    AND i.indisprimary AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
                    AND i.indimmediate AND i.indnatts=5 AND i.indnkeyatts=5 AND i.indkey::text='1 2 3 4 5'
                    AND i.indoption::text='0 0 0 0 0' AND i.indexprs IS NULL AND i.indpred IS NULL
                    AND NOT EXISTS (SELECT FROM unnest(i.indclass) x(op)
                        WHERE x.op<>(SELECT oc.oid FROM pg_catalog.pg_opclass oc
                            WHERE oc.opcnamespace='pg_catalog'::regnamespace AND oc.opcmethod=ix.relam AND oc.opcname='text_ops'))
                    AND NOT EXISTS (SELECT FROM unnest(i.indcollation) x(coll)
                        WHERE x.coll<>'pg_catalog."default"'::regcollation))
    ) THEN RAISE EXCEPTION 'selector move tuple stage shape changed' USING ERRCODE='P1034';END IF;

    -- Лимит применяется до агрегации. При выходе за предел не строим карту
    -- координат и не передаём частичный набор существующему компилятору.
    WITH sample AS MATERIALIZED (
        SELECT t.binding_id,octet_length(t.binding_id)::bigint+octet_length(t.side)+octet_length(t.object)
            +octet_length(t.fga_user)+octet_length(t.relation) AS row_bytes
        FROM ONLY pg_temp.kaname_role_stage_tuples t LIMIT p_rows-used_rows+1
    ), totals AS MATERIALIZED (
        SELECT count(*)::integer AS n,coalesce(sum(row_bytes),0)::bigint AS bytes FROM sample
    ), grouped AS (
        SELECT s.binding_id,count(*) AS n FROM sample s
        WHERE (SELECT t.n<=p_rows-used_rows AND t.bytes<=8388608 FROM totals t)
        GROUP BY s.binding_id
    )
    SELECT t.n,t.bytes,(SELECT coalesce(jsonb_object_agg(g.binding_id,g.n),'{}'::jsonb) FROM grouped g)
        INTO tuple_count,tuple_bytes,counts FROM totals t;
    IF tuple_count>p_rows-used_rows OR tuple_bytes>8388608 OR octet_length(counts::text)>8388608 THEN
        RAISE EXCEPTION 'selector move tuple stage exceeds budget' USING ERRCODE='54000';
    END IF;
    IF NOT p_retier AND tuple_count<>0 THEN
        RAISE EXCEPTION 'selector move has unexpected staged tuples' USING ERRCODE='P1034';
    END IF;
    RETURN jsonb_build_object('rows',used_rows+tuple_count,'reads',5,'tuples',tuple_count,'counts',counts);
END;
$census$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE grantee record;fn regprocedure:='kaname._authority_role_move_stage_tuple_census_v1(boolean,integer,integer)'::regprocedure;
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
DO $stage_tuples$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_role_move_sequence_prepare_v1(jsonb,jsonb,jsonb,integer,integer)','157d289b31d5bb2e1901df54ef5b60e9c08ace47518da56e0ffdff80c4c4a9fc','f0973c70d07bbd6c512136f3bc6876d0bd7543a16aed3db0d46f236fa581db91',$changes$[
  [
    " move_checks jsonb;move_frozen jsonb;move_extension jsonb;",
    " move_checks jsonb;move_frozen jsonb;move_extension jsonb;\n move_stage jsonb;move_stage_count integer;move_stage_matched integer:=0;"
  ],
  [
    " IF NOT creation AND promote THEN",
    " IF p_move IS NOT NULL THEN\n  move_stage:=kaname._authority_role_move_stage_tuple_census_v1(retier,p_rows-scanned,p_reads-reads);\n  scanned:=scanned+(move_stage->>'rows')::integer;\n  reads:=reads+(move_stage->>'reads')::integer;\n END IF;\n IF NOT creation AND promote THEN"
  ],
  [
    "    -- Сопоставление со spool не признаёт его программой: обе стороны заново",
    "    IF p_move IS NOT NULL THEN\n     -- Обе стороны EXCEPT читают только строки этого binding. Полная\n     -- перепись уже ограничила их размер и закрепила физическую таблицу.\n     move_stage_count:=coalesce((move_stage->'counts'->>(carrier->>'id'))::integer,0);\n     scanned:=scanned+2*move_stage_count;reads:=reads+2;\n     IF scanned>p_rows OR reads>p_reads THEN RAISE EXCEPTION 'selector move tuple comparison budget' USING ERRCODE='54000';END IF;\n     move_stage_matched:=move_stage_matched+move_stage_count;\n    END IF;\n    -- Сопоставление со spool не признаёт его программой: обе стороны заново"
  ],
  [
    "  -- Promotion идёт ПОСЛЕ retier всех bindings.",
    "  IF p_move IS NOT NULL AND move_stage_matched IS DISTINCT FROM (move_stage->>'tuples')::integer THEN\n   RAISE EXCEPTION 'selector move includes tuples outside the role compiler' USING ERRCODE='P1034';\n  END IF;\n  -- Promotion идёт ПОСЛЕ retier всех bindings."
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','0eb2a9eb2edcd6a5f4213dcf4f7570fe4ccac0d62a9939e863643756bf03c76d','97000d07f0b6396c3c95cd9ac00819642f49fa9c92b503befc57c3638edebcb5',$changes$[
  [
    " ('_authority_role_move_sequence_prepare_v1(jsonb,jsonb,jsonb,integer,integer)','157d289b31d5bb2e1901df54ef5b60e9c08ace47518da56e0ffdff80c4c4a9fc',false,'v',true,'private'),\n",
    " ('_authority_role_move_sequence_prepare_v1(jsonb,jsonb,jsonb,integer,integer)','f0973c70d07bbd6c512136f3bc6876d0bd7543a16aed3db0d46f236fa581db91',false,'v',true,'private'),\n ('_authority_role_move_stage_tuple_census_v1(boolean,integer,integer)','b14c4cae3e8cd03329139aeb83e13a0de0df6589453589f4fe56c1054197eb6a',false,'v',true,'private'),\n"
  ],
  [
    "  ('_authority_role_move_sequence_prepare_v1(jsonb,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_input','p_move','p_actor','p_rows','p_reads']),\n",
    "  ('_authority_role_move_sequence_prepare_v1(jsonb,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_input','p_move','p_actor','p_rows','p_reads']),\n  ('_authority_role_move_stage_tuple_census_v1(boolean,integer,integer)','jsonb',3,ARRAY['p_retier','p_rows','p_reads']),\n"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','6dd773315b80c6262d317ee415bf5092f038f616ec62054cea869e0683c80d18','0d79f56c1f2223464e356a58a727a08c937f9f4dc1e28ab46cdf9ae8ddf5c360',$changes$[
  [
    "0eb2a9eb2edcd6a5f4213dcf4f7570fe4ccac0d62a9939e863643756bf03c76d",
    "97000d07f0b6396c3c95cd9ac00819642f49fa9c92b503befc57c3638edebcb5"
  ]
]$changes$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','0ad2b530fe004c714ec1b5a3e156c06e93e1232dfd6267a452486e5a89f827c9','2ec5547197150217f89b63fe48573c59f983f3333ec5c781b881e10de7501feb',$changes$[
  [
    "0eb2a9eb2edcd6a5f4213dcf4f7570fe4ccac0d62a9939e863643756bf03c76d",
    "97000d07f0b6396c3c95cd9ac00819642f49fa9c92b503befc57c3638edebcb5"
  ],
  [
    "6dd773315b80c6262d317ee415bf5092f038f616ec62054cea869e0683c80d18",
    "0d79f56c1f2223464e356a58a727a08c937f9f4dc1e28ab46cdf9ae8ddf5c360"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'selector move tuple stage predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'selector move tuple stage replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move tuple stage body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move tuple stage installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selector move tuple stage storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$stage_tuples$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $stage_tuples$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('authority_metadata_service_account_access_label_ready_v1()','2ec5547197150217f89b63fe48573c59f983f3333ec5c781b881e10de7501feb','0ad2b530fe004c714ec1b5a3e156c06e93e1232dfd6267a452486e5a89f827c9',$changes$[
  [
    "0d79f56c1f2223464e356a58a727a08c937f9f4dc1e28ab46cdf9ae8ddf5c360",
    "6dd773315b80c6262d317ee415bf5092f038f616ec62054cea869e0683c80d18"
  ],
  [
    "97000d07f0b6396c3c95cd9ac00819642f49fa9c92b503befc57c3638edebcb5",
    "0eb2a9eb2edcd6a5f4213dcf4f7570fe4ccac0d62a9939e863643756bf03c76d"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','0d79f56c1f2223464e356a58a727a08c937f9f4dc1e28ab46cdf9ae8ddf5c360','6dd773315b80c6262d317ee415bf5092f038f616ec62054cea869e0683c80d18',$changes$[
  [
    "97000d07f0b6396c3c95cd9ac00819642f49fa9c92b503befc57c3638edebcb5",
    "0eb2a9eb2edcd6a5f4213dcf4f7570fe4ccac0d62a9939e863643756bf03c76d"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','97000d07f0b6396c3c95cd9ac00819642f49fa9c92b503befc57c3638edebcb5','0eb2a9eb2edcd6a5f4213dcf4f7570fe4ccac0d62a9939e863643756bf03c76d',$changes$[
  [
    "  ('_authority_role_move_sequence_prepare_v1(jsonb,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_input','p_move','p_actor','p_rows','p_reads']),\n  ('_authority_role_move_stage_tuple_census_v1(boolean,integer,integer)','jsonb',3,ARRAY['p_retier','p_rows','p_reads']),\n",
    "  ('_authority_role_move_sequence_prepare_v1(jsonb,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_input','p_move','p_actor','p_rows','p_reads']),\n"
  ],
  [
    " ('_authority_role_move_sequence_prepare_v1(jsonb,jsonb,jsonb,integer,integer)','f0973c70d07bbd6c512136f3bc6876d0bd7543a16aed3db0d46f236fa581db91',false,'v',true,'private'),\n ('_authority_role_move_stage_tuple_census_v1(boolean,integer,integer)','b14c4cae3e8cd03329139aeb83e13a0de0df6589453589f4fe56c1054197eb6a',false,'v',true,'private'),\n",
    " ('_authority_role_move_sequence_prepare_v1(jsonb,jsonb,jsonb,integer,integer)','157d289b31d5bb2e1901df54ef5b60e9c08ace47518da56e0ffdff80c4c4a9fc',false,'v',true,'private'),\n"
  ]
]$changes$::jsonb),
        ('_authority_role_move_sequence_prepare_v1(jsonb,jsonb,jsonb,integer,integer)','f0973c70d07bbd6c512136f3bc6876d0bd7543a16aed3db0d46f236fa581db91','157d289b31d5bb2e1901df54ef5b60e9c08ace47518da56e0ffdff80c4c4a9fc',$changes$[
  [
    "  IF p_move IS NOT NULL AND move_stage_matched IS DISTINCT FROM (move_stage->>'tuples')::integer THEN\n   RAISE EXCEPTION 'selector move includes tuples outside the role compiler' USING ERRCODE='P1034';\n  END IF;\n  -- Promotion идёт ПОСЛЕ retier всех bindings.",
    "  -- Promotion идёт ПОСЛЕ retier всех bindings."
  ],
  [
    "    IF p_move IS NOT NULL THEN\n     -- Обе стороны EXCEPT читают только строки этого binding. Полная\n     -- перепись уже ограничила их размер и закрепила физическую таблицу.\n     move_stage_count:=coalesce((move_stage->'counts'->>(carrier->>'id'))::integer,0);\n     scanned:=scanned+2*move_stage_count;reads:=reads+2;\n     IF scanned>p_rows OR reads>p_reads THEN RAISE EXCEPTION 'selector move tuple comparison budget' USING ERRCODE='54000';END IF;\n     move_stage_matched:=move_stage_matched+move_stage_count;\n    END IF;\n    -- Сопоставление со spool не признаёт его программой: обе стороны заново",
    "    -- Сопоставление со spool не признаёт его программой: обе стороны заново"
  ],
  [
    " IF p_move IS NOT NULL THEN\n  move_stage:=kaname._authority_role_move_stage_tuple_census_v1(retier,p_rows-scanned,p_reads-reads);\n  scanned:=scanned+(move_stage->>'rows')::integer;\n  reads:=reads+(move_stage->>'reads')::integer;\n END IF;\n IF NOT creation AND promote THEN",
    " IF NOT creation AND promote THEN"
  ],
  [
    " move_checks jsonb;move_frozen jsonb;move_extension jsonb;\n move_stage jsonb;move_stage_count integer;move_stage_matched integer:=0;",
    " move_checks jsonb;move_frozen jsonb;move_extension jsonb;"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'selector move tuple stage predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'selector move tuple stage replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move tuple stage body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move tuple stage installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selector move tuple stage storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$stage_tuples$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_role_move_stage_tuple_census_v1(boolean,integer,integer);
