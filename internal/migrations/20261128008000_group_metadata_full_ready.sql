-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- Полномочия исходного LOGIN и подписанный каталог проверяются на запуске.
-- Фасады затем требуют собственную аттестацию resource/decision контракта 2.
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_metadata_group_access_label_ready_v1()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $ready$
DECLARE
    runtime_oid oid:=session_user::regrole::oid;
    group_table regclass:=to_regclass('kaname.groups');
    bundle record;
    catalog_payload jsonb;
BEGIN
    IF current_setting('role') NOT IN ('none',session_user::text)
        OR kaname._authority_metadata_access_label_runtime_cohort_v2(runtime_oid) IS DISTINCT FROM true
        OR kaname._authority_role_actor_ordinary_login_v1(runtime_oid) IS DISTINCT FROM true
        OR kaname._authority_metadata_group_exports_v1(runtime_oid,false) IS NULL
        OR NOT EXISTS(SELECT FROM pg_catalog.pg_proc p
            WHERE p.oid=to_regprocedure('kaname.authority_metadata_access_label_ready_v2(text)')
                AND p.proowner=current_user::regrole
                AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='c3e85a3fddbb3b68e9ae040afc09a2242aca1f54f017a3c447ea4c5b6911fced')
        OR kaname.authority_metadata_access_label_ready_v2('metadata-access-label/owner-retention-v2') IS DISTINCT FROM true
        OR kaname._authority_access_label_freshness_storage_v1() IS DISTINCT FROM true THEN
        RETURN false;
    END IF;
    SELECT * INTO bundle FROM kaname.authority_protocol_read_bundle();
    IF NOT FOUND OR kaname.authority_full_contract_validate_v3(bundle.model_id,bundle.catalog_id,bundle.projector_version)
        IS DISTINCT FROM true THEN RETURN false; END IF;
    catalog_payload:=convert_from(bundle.catalog_json,'UTF8')::jsonb;
    IF NOT EXISTS(SELECT FROM jsonb_array_elements(catalog_payload#>'{Live,Resources}') r
        WHERE (r->>'Module',r->>'Resource',r->>'ObjectType')=('iam','group','iam_group'))
        OR EXISTS(SELECT FROM (VALUES ('group','update'),('accessLabel','apply')) required(resource,verb)
            WHERE NOT EXISTS(SELECT FROM jsonb_array_elements(catalog_payload#>'{Live,Verbs}') v
                WHERE (v->>'Module',v->>'Resource',v->>'Verb')=('iam',required.resource,required.verb))) THEN
        RETURN false;
    END IF;

    -- Проверяем тип физической строки, используемой для OLD/NEW, и уникальность имени при rename.
    IF NOT EXISTS(SELECT FROM pg_catalog.pg_class c WHERE c.oid=group_table AND c.relowner=current_user::regrole
        AND c.relkind='r' AND c.relpersistence='p' AND NOT(c.relrowsecurity OR c.relforcerowsecurity OR c.relhasrules OR c.relispartition)
        AND NOT EXISTS(SELECT FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid))
        OR (SELECT array_agg(a.attname::text||' '||a.atttypid::regtype::text ORDER BY a.attnum)
            FROM pg_catalog.pg_attribute a WHERE a.attrelid=group_table AND a.attnum>0 AND NOT a.attisdropped)
            IS DISTINCT FROM ARRAY['id text','account_id text','name text','description text','labels jsonb',
                'created_at timestamp with time zone','access_labels jsonb']
        OR EXISTS(SELECT FROM pg_catalog.pg_attribute a WHERE a.attrelid=group_table AND a.attnum>0
            AND NOT a.attisdropped AND (NOT a.attnotnull OR a.attgenerated<>'' OR a.attidentity<>''))
        OR EXISTS(SELECT FROM (VALUES ('groups_pkey','p','PRIMARY KEY (id)'),
                ('groups_account_name_unique','u','UNIQUE (account_id, name)')) required(name,kind,definition)
            WHERE NOT EXISTS(SELECT FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_index i ON i.indexrelid=c.conindid
                WHERE c.conrelid=group_table AND c.conname=required.name AND c.contype::text=required.kind
                    AND c.convalidated AND NOT c.condeferrable AND pg_get_constraintdef(c.oid)=required.definition
                    AND i.indisvalid AND i.indisready AND i.indislive AND i.indisunique AND i.indimmediate)) THEN
        RETURN false;
    END IF;

    -- Общий контракт проверяет штатные триггеры. Посторонний UPDATE-триггер
    -- мог бы изменить OLD/NEW или записать дополнительный эффект.
    IF (SELECT array_agg(t.tgname::text ORDER BY t.tgname::text COLLATE "C") FROM pg_catalog.pg_trigger t
        WHERE t.tgrelid=group_table AND NOT t.tgisinternal AND (t.tgtype::integer & 16)=16)
        IS DISTINCT FROM ARRAY['access_labels_000_commit_freshness','access_labels_immutable','authority_protocol_row',
            'authority_protocol_statement','authority_resource_effect_applied','binding_epoch_update',
            'groups_000_sequence_origin_update','groups_resource_journal_update_trg','policy_epoch_update',
            'registration_retired_legacy_seed_namespace_holds'] THEN
        RETURN false;
    END IF;
    IF EXISTS(SELECT FROM unnest(ARRAY['groups','users','service_accounts','projects','access_bindings','roles',
                'operations','authority_semantic_identity']) rel
            WHERE has_table_privilege(runtime_oid,to_regclass('kaname.'||rel),'SELECT') IS DISTINCT FROM true)
        OR EXISTS(SELECT FROM unnest(ARRAY['name','description','labels','access_labels']) col
            WHERE has_column_privilege(runtime_oid,group_table,col,'UPDATE') IS DISTINCT FROM true)
        OR has_table_privilege(runtime_oid,'kaname.operations','UPDATE') IS DISTINCT FROM true
        OR has_table_privilege(runtime_oid,'kaname.operations','INSERT') IS DISTINCT FROM true
        OR has_table_privilege(runtime_oid,'kaname.audit_outbox','INSERT') IS DISTINCT FROM true
        OR has_table_privilege(runtime_oid,'kaname.resource_reconcile_outbox','INSERT') IS DISTINCT FROM true
        OR has_sequence_privilege(runtime_oid,'kaname.resource_reconcile_outbox_id_seq','USAGE,UPDATE') IS DISTINCT FROM true THEN
        RETURN false;
    END IF;
    RETURN true;
END;
$ready$;
-- +goose StatementEnd

-- В одном перечне закреплены тела и ABI функций для выдачи прав и проверки
-- готовности. До первой выдачи все фасады должны принадлежать только владельцу.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_exports_v1(p_runtime oid,p_require_private boolean)
RETURNS regprocedure[] LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $exports$
DECLARE
    owner_oid oid:=current_user::regrole::oid;
    fn regprocedure;
    entry record;
    exports regprocedure[]:='{}';
    role_actor oid;
BEGIN
    IF owner_oid IS DISTINCT FROM (SELECT relowner FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass)
        OR p_require_private IS NULL THEN RETURN NULL; END IF;
    SELECT role_oid INTO role_actor FROM kaname.authority_role_actor_login WHERE singleton;
    FOR entry IN SELECT * FROM (VALUES
        ('_authority_metadata_group_accept_v1(text,text,integer,integer,integer)','1ef1a23ac0fdb61ec18b546a6a954ef88b19b6dc246b486164e75681860b10fb','plpgsql','v',false,'jsonb','p_actor_type,p_actor_id,p_rows,p_reads,p_work'),
        ('_authority_metadata_group_access_label_requirements_v1(integer,integer)','5df4d8501029e9ade25c9e17cd5fd282e3f21bd02af0c712e28857388998decf','plpgsql','v',false,'jsonb','p_rows,p_reads'),
        ('_authority_metadata_group_census_v1(text,jsonb,jsonb,integer,integer,integer)','ed8b59bb833d3fd0d5e94ec9d0a18f4ce8f66bf6b2cb6b396e8b8ab489b0fc55','plpgsql','s',false,'jsonb','p_root_type,p_old_root,p_new_labels,p_rows,p_reads,p_work'),
        ('_authority_metadata_group_closure_v1(jsonb,jsonb,integer,integer,integer)','58464957fd57b4cdaf730e1eb835c4a08d1e3fee3ce8540c58d148a205a24527','plpgsql','v',false,'jsonb','p_packet,p_catalog,p_rows,p_reads,p_work'),
        ('_authority_metadata_group_command_v1()','3104067d898986dfd59143b0442236c26ee258fa8fa28e5783b299449b52e208','plpgsql','v',false,'jsonb',NULL),
        ('_authority_metadata_group_compile_reserve_v1(jsonb,text,text,text,integer,integer,integer)','7e08a2757b1aa0d3bf87b1f33ccd42a14ed5a9e5d18795aa251e1717cef011fc','plpgsql','v',false,'jsonb','p_desired,p_audit,p_actor_type,p_actor_id,p_rows,p_reads,p_work'),
        ('_authority_metadata_group_compile_sources_v1(jsonb,text,text,integer,integer,integer)','515c77be132c0a2a67901149fa9be22ee99584e299bcef1f3b00498bcd8696fc','plpgsql','v',false,'jsonb','p_desired,p_actor_type,p_actor_id,p_rows,p_reads,p_work'),
        ('_authority_metadata_group_complete_v1()','30147ad90d393299f557c9a9c85e15d214da9e8798315a078a07d25553c15e02','plpgsql','v',false,'void',NULL),
        ('_authority_metadata_group_consume_v1(jsonb)','59844b861dfef890a90e92affb80ed1b1b458053b67a8a1e51511f573b0f8b46','plpgsql','v',false,'void','p_root_version'),
        ('_authority_metadata_group_held_replay_v1(integer,integer,integer)','f39c0e51902930b6efe63337f2962899c53ca66aecf9a97109e4d50051e55eac','plpgsql','v',false,'jsonb','p_rows,p_reads,p_work'),
        ('_authority_metadata_group_hold_and_replay_v1(jsonb,boolean,text,text,integer,integer,integer)','e6f31b9536054b390c2b8bb4d4d8abc0b7bec54f2773799afbf121644e51f23d','plpgsql','v',false,'jsonb','p_patch,p_rename,p_actor_type,p_actor_id,p_rows,p_reads,p_work'),
        ('_authority_metadata_group_member_partition_v1(text,text,text[],jsonb,jsonb,jsonb,integer,integer)','a763c093ce4412e52da32a8f19f964efa8fdc86fd4d3c65a8a6b252dd91dd951','plpgsql','i',false,'jsonb','p_root_type,p_root_id,p_bindings,p_index,p_catalog,p_frontiers,p_rows,p_work'),
        ('_authority_metadata_group_old_facts_v1(text,text,text[],jsonb,jsonb,jsonb,integer,integer)','7e46fcee2161c3899c7f1b27224ae0dc802d43bb2795a312782d9e27292408b7','plpgsql','i',false,'jsonb','p_root_type,p_root_id,p_bindings,p_index,p_catalog,p_frontiers,p_rows,p_work'),
        ('_authority_metadata_group_ordinary_accept_v1(text,text,integer,integer,integer)','9081c336ac803a08f2da92364695ec374fce091dcd7bbb173daa74e7a65fc245','plpgsql','v',false,'jsonb','p_actor_type,p_actor_id,p_rows,p_reads,p_work'),
        ('_authority_metadata_group_ordinary_command_v1()','40c6026a982144a38155a2f786bafbbab52aa77aedbcd100397c8c55a6f01d0c','plpgsql','v',false,'jsonb',NULL),
        ('_authority_metadata_group_ordinary_complete_v1()','9f7b2c2854c5cca8dcb4665a15a338fb2fe4813a094f6c4aa419449988490366','plpgsql','v',false,'void',NULL),
        ('_authority_metadata_group_ordinary_outputs_v1(jsonb,jsonb,text,text,bigint)','8cc35b4c04c74912a9712630caf9f6adcd61b7868c4b54457c15746498b51f39','plpgsql','s',false,'jsonb','p_old,p_new,p_actor,p_audit,p_reconcile'),
        ('_authority_metadata_group_ordinary_reserve_v1(text,text,text,jsonb,jsonb,text,text,text,integer,integer,integer)','1051baf3143def6f7f4e44a402d746d1a29c74ef61e527d4da3d5cad8b7fc5bc','plpgsql','v',false,'jsonb','p_id,p_xmin,p_ctid,p_old,p_patch,p_actor_type,p_actor_id,p_audit,p_rows,p_reads,p_work'),
        ('_authority_metadata_group_ordinary_versions_v1(jsonb)','e03f5dba1cdf98711293aaef5345594b547b641ef3b83efbf893cfce8e937389','plpgsql','v',false,'jsonb','p_program'),
        ('_authority_metadata_group_ordinary_write_v1(text)','9327f790f5d9cc2ab909e436f1636c35b263040021a8dedf125f539d5fef5253','plpgsql','v',false,'jsonb','p_id'),
        ('_authority_metadata_group_output_versions_v1(jsonb)','105d39221c8d2ca14978d7db368c7bfe5a43854f6baac4d7f60735dfbbc4223b','plpgsql','v',false,'jsonb','p_command'),
        ('_authority_metadata_group_prepare_v1(text,text,text,jsonb,jsonb,text,text,jsonb,text[],integer,integer,integer)','49f8c57372ed755e5b14a81d557f002e50e2dff0c837cf7ed19f7626db90e665','plpgsql','v',false,'TABLE(used_rows integer, used_reads integer, used_work integer)','p_id,p_xmin,p_ctid,p_old,p_new_access,p_actor_type,p_actor_id,p_policy_expected,p_policy_writes,p_rows,p_reads,p_work,used_rows,used_reads,used_work'),
        ('_authority_metadata_group_retention_compile_v1(jsonb,integer)','95c07af13e2824ba686f3a5b866056e8ba44c5bfe226cef50323b350ca932925','plpgsql','v',false,'jsonb','p_desired,p_work'),
        ('_authority_metadata_group_retention_plan_v1(jsonb,jsonb,jsonb,jsonb,text,jsonb,jsonb,integer)','089322e2575c95a7ba5f440bc9c53ce9855d255cf301cc866c50d94f28352d71','plpgsql','i',false,'jsonb','p_index,p_catalog,p_outputs,p_old_outputs,p_root_type,p_old,p_new,p_work'),
        ('_authority_metadata_group_retention_prepare_v1(jsonb,boolean,text,text,integer,integer,integer)','0844c47b8854cb8a9b61f0fca181bc8d910ff49adbba28797ad2658ac0483660','plpgsql','v',false,'jsonb','p_patch,p_rename,p_actor_type,p_actor_id,p_rows,p_reads,p_work'),
        ('_authority_metadata_group_target_hold_v1(text,text,integer,integer,integer)','d6cc4e6f20c3bb21ab40663b8764ba42bf9702079ec5881701ead5fc6aca745d','plpgsql','v',false,'jsonb','p_actor_type,p_actor_id,p_key_budget,p_rows,p_reads'),
        ('_authority_metadata_group_target_v1(text,text,text,jsonb,text,text,integer,integer)','e967d350798baa9769e29bed0658f129497d9282e2880a967e32a06783908c71','plpgsql','v',false,'jsonb','p_id,p_xmin,p_ctid,p_old,p_actor_type,p_actor_id,p_rows,p_reads'),
        ('_authority_metadata_group_trigger_v1(oid,text,text,jsonb,jsonb,text,text)','d93726479a48982fdc6fd435d5c00ac997eea17bf59183a79a5ab594745227aa','plpgsql','v',false,'jsonb','p_rel,p_name,p_timing,p_old,p_new,p_xmin,p_ctid'),
        ('_authority_metadata_group_write_v1(text)','2c19a5ab2ebbcb2226c1670fe9dbc9bc062179ca45ed306c255c24964e5f9094','plpgsql','v',false,'jsonb','p_group'),
        ('authority_metadata_group_accept_v1(text,text,integer,integer,integer)','af0d4dc61f81b039fc95c79ed284abfb53be1f1b8e8b44f2c3a0b134c5a83318','plpgsql','v',true,'jsonb','p_actor_type,p_actor_id,p_rows,p_reads,p_work'),
        ('authority_metadata_group_access_label_ready_v1()','042cf9e049cf12002f88b4b6bb5c45907a957e755f056f636dfc20d842b09ac3','plpgsql','s',true,'boolean',NULL),
        ('authority_metadata_group_ordinary_reserve_v1(text,text,text,jsonb,jsonb,text,text,text,integer,integer,integer)','9ac30ff7c1919243ee1ae597d273632a654f0b2c4bc6b218523597d1e1afe1a6','sql','v',true,'jsonb','p_id,p_xmin,p_ctid,p_old,p_patch,p_actor_type,p_actor_id,p_audit,p_rows,p_reads,p_work'),
        ('authority_metadata_group_prepare_v1(text,text,text,jsonb,jsonb,text,text,jsonb,text[],integer,integer,integer)','36f099111c31268332ba9e4fc698b1723068755d0932a414c22f15be006beaa1','sql','v',true,'TABLE(used_rows integer, used_reads integer, used_work integer)','p_id,p_xmin,p_ctid,p_old,p_access_labels,p_actor_type,p_actor_id,p_policy,p_writes,p_rows,p_reads,p_work,used_rows,used_reads,used_work'),
        ('authority_metadata_group_reserve_v1(jsonb,text,text,text,integer,integer,integer)','40333475a95056d13f5f2bf26a6b2a6a7b7e0f7a776cebb3db635da585c35f45','sql','v',true,'jsonb','p_desired,p_audit,p_actor_type,p_actor_id,p_rows,p_reads,p_work'),
        ('authority_metadata_group_retention_inputs_v1(jsonb,boolean,text,text,integer,integer,integer)','cb57f470237f517bee4b4d6b72ecd7c6d59d2aea35a034aa9169449a28d5751f','sql','v',true,'jsonb','p_patch,p_rename,p_actor_type,p_actor_id,p_rows,p_reads,p_work'),
        ('authority_metadata_group_write_v1(text)','271f645485babfe6f32ca8ccacf172b5c9058f1cf7cdcd3635fdec6c1a8194d5','plpgsql','v',true,'jsonb','p_id')
    ) expected(signature,digest,lang,volatility,definer,result_type,args) LOOP
        fn:=to_regprocedure('kaname.'||entry.signature);
        IF NOT EXISTS(SELECT FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
            WHERE p.oid=fn AND p.proowner=owner_oid AND p.prokind='f' AND p.prosecdef=entry.definer
                AND p.provolatile::text=entry.volatility AND l.lanname=entry.lang
                AND NOT(p.proisstrict OR p.proleakproof) AND p.proparallel='u'
                AND p.pronargdefaults=0 AND p.provariadic=0 AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
                AND p.proargnames IS NOT DISTINCT FROM string_to_array(entry.args,',')
                AND pg_get_function_result(p.oid)=entry.result_type
                AND CASE WHEN entry.result_type LIKE 'TABLE(%' THEN
                    p.proretset AND p.prorettype='record'::regtype AND
                    p.proargmodes::text[]=array_fill('i'::text,ARRAY[p.pronargs::integer])||ARRAY['t','t','t']
                    ELSE NOT p.proretset AND p.proargmodes IS NULL AND p.proallargtypes IS NULL END
                AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=entry.digest
                AND NOT EXISTS(SELECT FROM pg_catalog.pg_proc other WHERE other.pronamespace=p.pronamespace
                    AND other.proname=p.proname AND other.oid<>p.oid)
                AND NOT EXISTS(SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
                    WHERE a.grantee<>owner_oid AND (p_require_private OR NOT entry.definer OR a.grantee=0
                        OR a.grantor<>owner_oid OR a.privilege_type<>'EXECUTE' OR a.is_grantable
                        OR kaname._authority_metadata_access_label_runtime_cohort_v2(a.grantee) IS DISTINCT FROM true
                        OR kaname._authority_role_actor_ordinary_login_v1(a.grantee) IS DISTINCT FROM true))
                AND (NOT entry.definer OR p_runtime IS NULL OR EXISTS(SELECT FROM aclexplode(p.proacl) a
                    WHERE a.grantee=p_runtime AND a.privilege_type='EXECUTE' AND NOT a.is_grantable))
                AND (role_actor IS NULL OR has_function_privilege(role_actor,p.oid,'EXECUTE') IS FALSE)) THEN
            RETURN NULL;
        END IF;
        IF entry.definer THEN exports:=array_append(exports,fn); END IF;
    END LOOP;
    RETURN exports;
END;
$exports$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_grant_v1(p_runtime regrole)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $grant$
DECLARE
    runtime_name name;
    exports regprocedure[];
    fn regprocedure;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF kaname._authority_metadata_access_label_runtime_cohort_v2(p_runtime::oid) IS DISTINCT FROM true
        OR kaname._authority_role_actor_ordinary_login_v1(p_runtime::oid) IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'group metadata requires the enrolled runtime login' USING ERRCODE='42501';
    END IF;
    SELECT rolname INTO STRICT runtime_name FROM pg_catalog.pg_roles WHERE oid=p_runtime::oid;
    exports:=kaname._authority_metadata_group_exports_v1(NULL,false);
    IF exports IS NULL THEN
        RAISE EXCEPTION 'group metadata functions differ from their contract' USING ERRCODE='55000';
    END IF;
    FOREACH fn IN ARRAY exports LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %I',fn,runtime_name);
    END LOOP;
END;
$grant$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $close$
DECLARE
    signature text;
    fn regprocedure;
    recipient record;
BEGIN
    FOREACH signature IN ARRAY ARRAY[
        'authority_metadata_group_access_label_ready_v1()',
        '_authority_metadata_group_exports_v1(oid,boolean)',
        '_authority_metadata_group_grant_v1(regrole)'
    ] LOOP
        fn:=to_regprocedure('kaname.'||signature);
        FOR recipient IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE p.oid=fn AND a.grantee<>p.proowner
        LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
                CASE WHEN recipient.grantee=0 THEN 'PUBLIC' ELSE quote_ident(recipient.rolname) END);
        END LOOP;
    END LOOP;
END;
$close$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
BEGIN
    IF kaname._authority_metadata_group_exports_v1(NULL,true) IS NULL THEN
        RAISE EXCEPTION 'group metadata predecessor differs or already has runtime grants' USING ERRCODE='55000';
    END IF;
END;
$private$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $storage_contract$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
    ('_authority_sequence_complete_v3()','8e151549f6e4ee12f3dc51003e59ecd3b0464fafaee7f484fde45b3cd4874850','36bbee5adceb061f8c884b2d1ce18557fcfc318c949baaa563db789561dd06b3',
    $changes$[
 [
  " IF program->>'family'='metadata' AND program#>>'{frozen,mode}'='group_access_labels' THEN",
  " IF program->>'family'='metadata' AND program#>>'{frozen,mode}' IN ('group_ordinary','group_noop') THEN\n  PERFORM kaname._authority_metadata_group_ordinary_complete_v1();\n END IF;\n IF program->>'family'='metadata' AND program#>>'{frozen,mode}'='group_access_labels' THEN"
 ]
]$changes$::jsonb),
    ('_authority_metadata_mirror_grant_v1(regrole)','894c502c7964cd37d073107df6b5eed59a16f02228b3a7352fb50cf13e47d8a7','9ced0baa8705dc3cfe66fa225320ed92c10b9970c0a11cec1aab349dcd8fcb11',
    $changes$[
 [
  " END LOOP;\nEND;",
  " END LOOP;\n PERFORM kaname._authority_metadata_group_grant_v1(p_runtime);\nEND;"
 ]
]$changes$::jsonb),
    ('_authority_crud_storage_v3()','340900a3ba449ae39faab747b0dbdb844fd528c319c90899e8682fdc5db78d91','e5250e124e4648060903596c2291de971d58159b416cd6a80428bf9885fce5b2',
    $changes$[
 [
  "8e151549f6e4ee12f3dc51003e59ecd3b0464fafaee7f484fde45b3cd4874850",
  "36bbee5adceb061f8c884b2d1ce18557fcfc318c949baaa563db789561dd06b3"
 ],
 [
  "894c502c7964cd37d073107df6b5eed59a16f02228b3a7352fb50cf13e47d8a7",
  "9ced0baa8705dc3cfe66fa225320ed92c10b9970c0a11cec1aab349dcd8fcb11"
 ],
 [
  " ('_authority_metadata_group_complete_v1()','30147ad90d393299f557c9a9c85e15d214da9e8798315a078a07d25553c15e02',false,'v',true,'private'),",
  " ('_authority_metadata_group_complete_v1()','30147ad90d393299f557c9a9c85e15d214da9e8798315a078a07d25553c15e02',false,'v',true,'private'),\n ('_authority_metadata_group_exports_v1(oid,boolean)','3234dd763c77c78dee8e3cd67984b6de014fd56bf43219a43146bbd4b01ce456',false,'s',true,'private'),\n ('_authority_metadata_group_grant_v1(regrole)','4f7b7648ee6e5381cdee74450718d0bd70aaa5256687148d5afc06f27cb89172',false,'v',true,'private'),"
 ],
 [
  "  ('_authority_metadata_group_complete_v1()','void',0,NULL::text[]),",
  "  ('_authority_metadata_group_complete_v1()','void',0,NULL::text[]),\n  ('_authority_metadata_group_exports_v1(oid,boolean)','regprocedure[]',2,ARRAY['p_runtime','p_require_private']),\n  ('_authority_metadata_group_grant_v1(regrole)','void',1,ARRAY['p_runtime']),"
 ]
]$changes$::jsonb),
    ('_authority_full_contract_storage_v3()','f608fe1d4c44496bc9392176c3f687a960ab0eb4145563c8fbbc10a76d7d7e71','7e9ef290479a7ab33c091251069ae2a63684c19094104180131808c1c81fe381',
    $changes$[
 [
  "340900a3ba449ae39faab747b0dbdb844fd528c319c90899e8682fdc5db78d91",
  "e5250e124e4648060903596c2291de971d58159b416cd6a80428bf9885fce5b2"
 ]
]$changes$::jsonb),
    ('authority_metadata_service_account_access_label_ready_v1()','f0f70bf324e747620a4f97059720a7e6eb9920a81e1ed0df4d56a8d8c8fe0efc','91b537ba372c6510936664ff6ee7c58d4ee608a7963723461544cf97379cb9e2',
    $changes$[
 [
  "340900a3ba449ae39faab747b0dbdb844fd528c319c90899e8682fdc5db78d91",
  "e5250e124e4648060903596c2291de971d58159b416cd6a80428bf9885fce5b2"
 ],
 [
  "f608fe1d4c44496bc9392176c3f687a960ab0eb4145563c8fbbc10a76d7d7e71",
  "7e9ef290479a7ab33c091251069ae2a63684c19094104180131808c1c81fe381"
 ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'group metadata contract predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'group metadata contract replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'group metadata contract body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'group metadata contract installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'group metadata full storage contract differs' USING ERRCODE='55000';
    END IF;
END;
$storage_contract$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $backfill$
DECLARE recipient record;
BEGIN
    FOR recipient IN SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolcanlogin
        AND kaname._authority_metadata_access_label_runtime_cohort_v2(r.oid)
        AND kaname._authority_role_actor_ordinary_login_v1(r.oid) LOOP
        PERFORM kaname._authority_metadata_group_grant_v1(recipient.oid::regrole);
    END LOOP;
END;
$backfill$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $close$
DECLARE
    signature text;
    fn regprocedure;
    recipient record;
BEGIN
    FOREACH signature IN ARRAY ARRAY[
        'authority_metadata_group_accept_v1(text,text,integer,integer,integer)',
        'authority_metadata_group_access_label_ready_v1()',
        'authority_metadata_group_ordinary_reserve_v1(text,text,text,jsonb,jsonb,text,text,text,integer,integer,integer)',
        'authority_metadata_group_prepare_v1(text,text,text,jsonb,jsonb,text,text,jsonb,text[],integer,integer,integer)',
        'authority_metadata_group_reserve_v1(jsonb,text,text,text,integer,integer,integer)',
        'authority_metadata_group_retention_inputs_v1(jsonb,boolean,text,text,integer,integer,integer)',
        'authority_metadata_group_write_v1(text)'
    ] LOOP
        fn:=to_regprocedure('kaname.'||signature);
        FOR recipient IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE p.oid=fn AND a.grantee<>p.proowner
        LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
                CASE WHEN recipient.grantee=0 THEN 'PUBLIC' ELSE quote_ident(recipient.rolname) END);
        END LOOP;
    END LOOP;
END;
$close$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $storage_contract$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
    ('authority_metadata_service_account_access_label_ready_v1()','91b537ba372c6510936664ff6ee7c58d4ee608a7963723461544cf97379cb9e2','f0f70bf324e747620a4f97059720a7e6eb9920a81e1ed0df4d56a8d8c8fe0efc',
    $changes$[
 [
  "7e9ef290479a7ab33c091251069ae2a63684c19094104180131808c1c81fe381",
  "f608fe1d4c44496bc9392176c3f687a960ab0eb4145563c8fbbc10a76d7d7e71"
 ],
 [
  "e5250e124e4648060903596c2291de971d58159b416cd6a80428bf9885fce5b2",
  "340900a3ba449ae39faab747b0dbdb844fd528c319c90899e8682fdc5db78d91"
 ]
]$changes$::jsonb),
    ('_authority_full_contract_storage_v3()','7e9ef290479a7ab33c091251069ae2a63684c19094104180131808c1c81fe381','f608fe1d4c44496bc9392176c3f687a960ab0eb4145563c8fbbc10a76d7d7e71',
    $changes$[
 [
  "e5250e124e4648060903596c2291de971d58159b416cd6a80428bf9885fce5b2",
  "340900a3ba449ae39faab747b0dbdb844fd528c319c90899e8682fdc5db78d91"
 ]
]$changes$::jsonb),
    ('_authority_crud_storage_v3()','e5250e124e4648060903596c2291de971d58159b416cd6a80428bf9885fce5b2','340900a3ba449ae39faab747b0dbdb844fd528c319c90899e8682fdc5db78d91',
    $changes$[
 [
  "  ('_authority_metadata_group_complete_v1()','void',0,NULL::text[]),\n  ('_authority_metadata_group_exports_v1(oid,boolean)','regprocedure[]',2,ARRAY['p_runtime','p_require_private']),\n  ('_authority_metadata_group_grant_v1(regrole)','void',1,ARRAY['p_runtime']),",
  "  ('_authority_metadata_group_complete_v1()','void',0,NULL::text[]),"
 ],
 [
  " ('_authority_metadata_group_complete_v1()','30147ad90d393299f557c9a9c85e15d214da9e8798315a078a07d25553c15e02',false,'v',true,'private'),\n ('_authority_metadata_group_exports_v1(oid,boolean)','3234dd763c77c78dee8e3cd67984b6de014fd56bf43219a43146bbd4b01ce456',false,'s',true,'private'),\n ('_authority_metadata_group_grant_v1(regrole)','4f7b7648ee6e5381cdee74450718d0bd70aaa5256687148d5afc06f27cb89172',false,'v',true,'private'),",
  " ('_authority_metadata_group_complete_v1()','30147ad90d393299f557c9a9c85e15d214da9e8798315a078a07d25553c15e02',false,'v',true,'private'),"
 ],
 [
  "9ced0baa8705dc3cfe66fa225320ed92c10b9970c0a11cec1aab349dcd8fcb11",
  "894c502c7964cd37d073107df6b5eed59a16f02228b3a7352fb50cf13e47d8a7"
 ],
 [
  "36bbee5adceb061f8c884b2d1ce18557fcfc318c949baaa563db789561dd06b3",
  "8e151549f6e4ee12f3dc51003e59ecd3b0464fafaee7f484fde45b3cd4874850"
 ]
]$changes$::jsonb),
    ('_authority_metadata_mirror_grant_v1(regrole)','9ced0baa8705dc3cfe66fa225320ed92c10b9970c0a11cec1aab349dcd8fcb11','894c502c7964cd37d073107df6b5eed59a16f02228b3a7352fb50cf13e47d8a7',
    $changes$[
 [
  " END LOOP;\n PERFORM kaname._authority_metadata_group_grant_v1(p_runtime);\nEND;",
  " END LOOP;\nEND;"
 ]
]$changes$::jsonb),
    ('_authority_sequence_complete_v3()','36bbee5adceb061f8c884b2d1ce18557fcfc318c949baaa563db789561dd06b3','8e151549f6e4ee12f3dc51003e59ecd3b0464fafaee7f484fde45b3cd4874850',
    $changes$[
 [
  " IF program->>'family'='metadata' AND program#>>'{frozen,mode}' IN ('group_ordinary','group_noop') THEN\n  PERFORM kaname._authority_metadata_group_ordinary_complete_v1();\n END IF;\n IF program->>'family'='metadata' AND program#>>'{frozen,mode}'='group_access_labels' THEN",
  " IF program->>'family'='metadata' AND program#>>'{frozen,mode}'='group_access_labels' THEN"
 ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'group metadata contract predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'group metadata contract replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'group metadata contract body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'group metadata contract installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'group metadata full storage contract differs' USING ERRCODE='55000';
    END IF;
END;
$storage_contract$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_metadata_group_grant_v1(regrole);
DROP FUNCTION kaname._authority_metadata_group_exports_v1(oid,boolean);
DROP FUNCTION kaname.authority_metadata_group_access_label_ready_v1();
