-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- Отдельное разрешение User.Update относится к уже назначенной паре LOGIN.
-- При ротации или переустановке пары штатный Role configure отзывает её прежние ACL.
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_metadata_user_access_label_ready_v1() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $ready$
DECLARE pair kaname.authority_role_actor_login%ROWTYPE;
BEGIN
    SELECT * INTO pair FROM ONLY kaname.authority_role_actor_login WHERE singleton;
    IF NOT FOUND OR kaname.authority_role_actor_pair_ready_v1(pair.runtime_oid,pair.runtime_name::text) IS DISTINCT FROM true
        OR kaname._authority_metadata_user_exports_v1(pair.role_oid,true) IS NULL THEN
        RETURN false;
    END IF;
    RETURN true;
END;
$ready$;

-- Единый список для допуска и отзыва. Триггерные SECURITY DEFINER остаются приватными.
CREATE FUNCTION kaname._authority_metadata_user_exports_v1(p_executor oid,p_installed boolean)
RETURNS regprocedure[] LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $exports$
DECLARE
    owner_oid oid:=current_user::regrole::oid;
    pair kaname.authority_role_actor_login%ROWTYPE;
    entry record;
    fn regprocedure;
    exported boolean;
    exports regprocedure[]:='{}';
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF EXISTS(SELECT FROM (VALUES
        ('_authority_full_contract_storage_v3()','c2f591a96b9a63b616ba4c29b41f9a738bbaa61647f5c6a5b900674ecd747318'),
        ('authority_access_label_storage_valid_v1()','2677e3402d1966ac473c6b2253977f9b04af4d854957a7c976da1736fde40c90'),
        ('_authority_access_label_freshness_storage_v1()','2ae2a6ff97608b798e664995ac982845de380d936cee83815eaa0eb86569227b')
    ) dep(signature,digest) WHERE NOT EXISTS(SELECT FROM pg_catalog.pg_proc p
        WHERE p.oid=to_regprocedure('kaname.'||dep.signature) AND p.proowner=owner_oid
            AND p.prosecdef AND p.prokind='f' AND p.provolatile='s' AND NOT (p.proretset OR p.proisstrict OR p.proleakproof)
            AND p.prorettype='boolean'::regtype AND p.proargnames IS NULL AND p.proargmodes IS NULL
            AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
            AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=dep.digest)) THEN RETURN NULL; END IF;
    SELECT e.* INTO pair FROM ONLY kaname.authority_role_actor_login e
    JOIN pg_catalog.pg_roles r ON (r.oid,r.rolname)=(e.runtime_oid,e.runtime_name)
    JOIN pg_catalog.pg_roles s ON (s.oid,s.rolname)=(e.role_oid,e.role_name)
    WHERE e.singleton AND e.role_oid=p_executor AND e.role_oid<>e.runtime_oid;
    IF NOT FOUND OR p_installed IS NULL
        OR NOT kaname._authority_role_actor_ordinary_login_v1(pair.runtime_oid)
        OR NOT kaname._authority_role_actor_ordinary_login_v1(pair.role_oid)
        OR EXISTS(SELECT FROM pg_catalog.pg_auth_members WHERE roleid=pair.role_oid)
        OR kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true
        OR kaname._authority_access_label_freshness_storage_v1() IS DISTINCT FROM true THEN RETURN NULL; END IF;

    -- Обычный runtime обеспечивает исходные ACL, отдельный LOGIN читает источники
    -- решения и меняет User и его операцию исключительно через закреплённые входы.
    IF NOT has_schema_privilege(pair.runtime_oid,'kaname','USAGE')
        OR EXISTS(SELECT FROM unnest(ARRAY['users','memberships','operations']) tbl
            WHERE NOT has_table_privilege(pair.runtime_oid,to_regclass('kaname.'||tbl),'SELECT'))
        OR EXISTS(SELECT FROM unnest(ARRAY['users','memberships']) tbl
            WHERE NOT has_table_privilege(pair.role_oid,to_regclass('kaname.'||tbl),'SELECT'))
        OR EXISTS(SELECT FROM unnest(ARRAY['labels','access_labels']) col
            WHERE NOT has_column_privilege(pair.runtime_oid,'kaname.users',col,'UPDATE'))
        OR EXISTS(SELECT FROM unnest(ARRAY['id','description','created_at','created_by','modified_at','done',
            'metadata_type','metadata_data','resource_id','account_id','principal_type','principal_id','principal_display_name']) col
            WHERE NOT has_column_privilege(pair.runtime_oid,'kaname.operations',col,'INSERT'))
        OR EXISTS(SELECT FROM unnest(ARRAY['done','modified_at','response_type','response_data']) col
            WHERE NOT has_column_privilege(pair.runtime_oid,'kaname.operations',col,'UPDATE'))
        OR NOT has_table_privilege(pair.runtime_oid,'kaname.audit_outbox','INSERT')
        OR NOT has_table_privilege(pair.runtime_oid,'kaname.resource_reconcile_outbox','INSERT')
        OR NOT has_sequence_privilege(pair.runtime_oid,'kaname.resource_reconcile_outbox_id_seq','USAGE,UPDATE')
        OR has_any_column_privilege(pair.role_oid,'kaname.users','INSERT,UPDATE')
        OR has_table_privilege(pair.role_oid,'kaname.users','DELETE,TRUNCATE')
        OR has_any_column_privilege(pair.role_oid,'kaname.operations','SELECT,INSERT,UPDATE')
        OR has_table_privilege(pair.role_oid,'kaname.operations','DELETE,TRUNCATE')
        OR has_function_privilege(pair.role_oid,'kaname.authority_scalar_sequence_finalize_v3()','EXECUTE')
        THEN RETURN NULL; END IF;

    -- WHEN имеет значение: одним именем можно скрыть триггер, который никогда не срабатывает.
    IF EXISTS(SELECT FROM (VALUES
        ('insert',5,'new.user_access_labels'),('update',17,'old.user_access_labelsORnew.user_access_labels'),
        ('interrupt',19,'old.user_access_labelsANDnew.user_access_labelsANDNOTold.doneANDnew.doneANDnew.error_codeISNULLANDnew.error_messageISNULLANDnew.error_detailsISNULLANDnew.response_type=''type.googleapis.com/kaname.cloud.iam.v1.User''ANDnew.response_dataISNOTNULL'),
        ('delete',9,'old.user_access_labelsANDNOTold.done'),('truncate',34,NULL)
    ) guard(suffix,kind,predicate) WHERE NOT EXISTS(SELECT FROM pg_catalog.pg_trigger t
        WHERE t.tgrelid='kaname.operations'::regclass AND t.tgname='user_access_labels_operation_'||guard.suffix
            AND t.tgfoid='kaname._authority_user_access_labels_operation_guard_v1()'::regprocedure
            AND t.tgtype=guard.kind AND t.tgenabled='A' AND NOT t.tgisinternal AND t.tgnargs=0
            AND t.tgattr=''::int2vector AND t.tgconstraint=0 AND NOT t.tgdeferrable AND NOT t.tginitdeferred
            AND regexp_replace(replace(substring(pg_get_triggerdef(t.oid) FROM ' WHEN [(](.*)[)] EXECUTE FUNCTION '),
                '::text',''),'[()[:space:]]','','g') IS NOT DISTINCT FROM guard.predicate)) THEN RETURN NULL; END IF;
    FOR entry IN SELECT * FROM (VALUES
        ('_authority_metadata_user_access_label_freshness_v1()','cae7faa2799cf717dcd71a30c3c37a2eade81389278dcce5ced244297a26eb91','plpgsql','v',false,'trigger',NULL),
        ('_authority_metadata_user_access_label_requirements_v1(integer,integer)','91a08d260772585df046c57b254e2a19e686e3484c95c574075b76c7c6c8623d','plpgsql','v',false,'jsonb','p_rows,p_reads'),
        ('_authority_metadata_user_apply_sources_v1(integer,integer)','6ad536360d3af1389e4c1e0032b65bf4906512b17ffd311c3bbf277ba758f7df','plpgsql','v',false,'jsonb','p_rows,p_reads'),
        ('_authority_metadata_user_carry_v1(integer,integer)','5887dceebe65dbb469df942069312ef277335a69d2db509d965e00ac619afdcf','plpgsql','v',false,'jsonb','p_rows,p_reads'),
        ('_authority_metadata_user_census_v1(jsonb,integer,integer,integer)','9da0a65cdb0d3f6263b2ad4f2ffebf5b5805d796b16994ee4f7f23294055e9cd','plpgsql','s',false,'jsonb','p_target,p_rows,p_reads,p_work'),
        ('_authority_metadata_user_closure_v1(jsonb,jsonb,integer,integer,integer)','b96cfa3454348ce44bd1bb4af012f903df53775296927f272ced3ba288838588','plpgsql','v',false,'jsonb','p_packet,p_catalog,p_rows,p_reads,p_work'),
        ('_authority_metadata_user_enrollment_v1()','11e3150b360761978624fc4a8b9489206625b9c9ef209a98b9ef348393d75a62','plpgsql','v',false,'jsonb',NULL),
        ('_authority_metadata_user_freeze_images_v1(text,text,integer,integer)','6886c0e2338b147316a8bf2394bbe793a2d35ffe07c6dbd50e8086791af4b4ae','plpgsql','v',false,'jsonb','p_actor_type,p_actor_id,p_rows,p_reads'),
        ('_authority_metadata_user_freshness_assert_v1()','0ce926ffece76d7c1c7fffe31a540f65bad7110fe419e743336126c0d3e3d670','plpgsql','v',false,'void',NULL),
        ('_authority_metadata_user_freshness_command_v1()','4ec5d2c0c6798e3c70c7aeb58b791c26359f2e50a0c346a5d06db22f4fe20d98','plpgsql','v',false,'jsonb',NULL),
        ('_authority_metadata_user_held_replay_v1(integer,integer,integer)','f772c1035bdbffbaae57e10cabbd22af7cf52a5844b49282ef1cbed9f7d73586','plpgsql','v',false,'jsonb','p_rows,p_reads,p_work'),
        ('_authority_metadata_user_hold_and_replay_v1(text,text,integer,integer,integer)','8992d328d7982664bf46b086cb0253d9b55b90c6924b619c608020753349aa0f','plpgsql','v',false,'jsonb','p_actor_type,p_actor_id,p_rows,p_reads,p_work'),
        ('_authority_metadata_user_hold_apply_and_carry_v1(integer,integer)','3a73fd5d03ce7af900aec79c3f810647e006c9d0299e1fc78ac069e70af65132','plpgsql','v',false,'jsonb','p_rows,p_reads'),
        ('_authority_metadata_user_member_partition_v1(text,text,text[],jsonb,jsonb,jsonb,integer,integer)','a399b12146c382fbd910d6529ed8bb9c0ee65038e75b27443b67cc9062c3141f','plpgsql','i',false,'jsonb','p_root_type,p_root_id,p_bindings,p_index,p_catalog,p_frontiers,p_rows,p_work'),
        ('_authority_metadata_user_noop_commit_v1()','2ed2f252361b97cf84afba68ed2fdd78e0ddf9c1d2e31dbc5431f64733af54c1','plpgsql','v',true,'trigger',NULL),
        ('_authority_metadata_user_noop_complete_v1(text,uuid,timestamptz,bytea)','def1bd362158dd3e1e6e02656255ee630dcebc8f9647f15bffc1b2bcb3516735','plpgsql','v',false,'kaname.operations','p_op,p_nonce,p_decision,p_response'),
        ('_authority_metadata_user_noop_reserve_v1(text,timestamptz,bytea,text,text,text,text,integer,integer)','fd3bec23fd73e58697dad2668375cb0eb22a02dd06636d83d5fe5c0a85ecf41c','plpgsql','v',false,'jsonb','p_op,p_created,p_metadata,p_account,p_actor_type,p_actor_id,p_display,p_rows,p_reads'),
        ('_authority_metadata_user_noop_transition_v1(text,jsonb,jsonb)','aaf3a7b4157c1106c1b9820dd27ed3c44061803bcd869cdcea33aa8f79f39ddc','plpgsql','v',false,'boolean','p_when,p_old,p_new'),
        ('_authority_metadata_user_old_facts_v1(text,text,text[],jsonb,jsonb,jsonb,integer,integer)','e9e713adac23233d139105c45e22cb4833abd6aafaa29e9b278f39eb764c8d27','plpgsql','i',false,'jsonb','p_root_type,p_root_id,p_bindings,p_index,p_catalog,p_frontiers,p_rows,p_work'),
        ('_authority_metadata_user_ordinary_commit_v1()','abff163a2ac3a7e5148ec44181ca115f21be07fff6a1cfe66732113b631ead4c','plpgsql','v',true,'trigger',NULL),
        ('_authority_metadata_user_ordinary_complete_v1(text,uuid,timestamptz,bytea)','675bcd6a9a8db783d5bfcc8ee4a8f8662e3d7c7099f6576cd92b15fc00c4067b','plpgsql','v',false,'kaname.operations','p_op,p_nonce,p_decision,p_response'),
        ('_authority_metadata_user_ordinary_effects_v1(text)','47379e34ac5c5e0441763514d183a0ee15620d8d6ab181d83aae2613703cc386','plpgsql','v',false,'jsonb','p_audit'),
        ('_authority_metadata_user_ordinary_reserve_v1(text,timestamptz,bytea,text,text,text,text,integer,integer,text)','402b06e4819a8714f734afe01aefa3450d2ee65e8d635a42d30fd24faeb799fc','plpgsql','v',false,'jsonb','p_op,p_created,p_metadata,p_account,p_actor_type,p_actor_id,p_display,p_rows,p_reads,p_audit'),
        ('_authority_metadata_user_ordinary_versions_v1()','00c66bd7f54f9d4914aa61b73997c6da7dd076b32be55bdf56eca24b2ea96259','plpgsql','v',false,'jsonb',NULL),
        ('_authority_metadata_user_ordinary_write_v1(text,uuid,timestamptz)','ed62971ca486ab7aedc34a8075a9adacd70627218145816dfb5044b9ac066d80','plpgsql','v',false,'jsonb','p_op,p_nonce,p_decision'),
        ('_authority_metadata_user_patch_images_v1(jsonb,jsonb)','bef76eca617b2b780f7dcfc0272f8587e86a476094f7b0dc217042413e001a9f','plpgsql','i',false,'jsonb','p_old,p_patch'),
        ('_authority_metadata_user_patch_target_v1(text,text,text,jsonb,jsonb,jsonb,text,text,integer,integer)','38439ffbecb99ed240183cb5730250ad99e8dac01fbb869d6e6ae05b0c23cfed','plpgsql','v',false,'jsonb','p_id,p_xmin,p_ctid,p_old,p_memberships,p_patch,p_actor_type,p_actor_id,p_rows,p_reads'),
        ('_authority_metadata_user_prepare_v1(text,text,text,jsonb,jsonb,jsonb,text,text,jsonb,integer,integer,integer)','98ff07a708a4866d83c7e0dadda53cb6e06c5e6e640f7e61dcd3581171fff42f','plpgsql','v',false,'TABLE(used_rows integer, used_reads integer, used_work integer)','p_id,p_xmin,p_ctid,p_old,p_memberships,p_patch,p_actor_type,p_actor_id,p_policy_expected,p_rows,p_reads,p_work,used_rows,used_reads,used_work'),
        ('_authority_metadata_user_protected_approve_v1(text,uuid,timestamptz,integer,integer,integer)','b608cd236554d4e0768fd3b1ec6d12e35f58282ca5210851b9f72254d008ee6b','plpgsql','v',false,'jsonb','p_op,p_nonce,p_decision,p_rows,p_reads,p_work'),
        ('_authority_metadata_user_protected_commit_v1()','557afff6f9c9b3d1df865fe6622436e38e2fec58241ad72b855c3fa363b2242c','plpgsql','v',true,'trigger',NULL),
        ('_authority_metadata_user_protected_complete_v1(text,uuid,timestamptz,bytea)','ae2f510abbea172a8156d2ecdfe4228aad2b5cdfd3c8aae907cc3ff419b4abf9','plpgsql','v',false,'kaname.operations','p_op,p_nonce,p_decision,p_response'),
        ('_authority_metadata_user_protected_effects_v1(text)','d1ad5d32a979e48dba11f81fb8e47556dc9f9e29900fccfbbbf3b108f4d9d90b','plpgsql','v',false,'jsonb','p_audit'),
        ('_authority_metadata_user_protected_program_v1(jsonb,integer,integer,integer)','4024ece7963d5aea874c540c3740e4ea410dd2c716978f45f3b246a7e714e60a','plpgsql','v',false,'jsonb','p_desired,p_rows,p_reads,p_work'),
        ('_authority_metadata_user_protected_reserve_v1(text,timestamptz,bytea,text,text,text,text,integer,integer,text,jsonb,integer)','4e1d0f5d9e46cd44cb7763831f37f9b95f4e49e390090a2604450e64cfe0dad6','plpgsql','v',false,'jsonb','p_op,p_created,p_metadata,p_account,p_actor_type,p_actor_id,p_display,p_rows,p_reads,p_audit,p_desired,p_work'),
        ('_authority_metadata_user_protected_versions_v1()','ffe733e170d7eb30d7f5361851ecc30d8093365a35c1f429739914c9becb165f','plpgsql','v',false,'jsonb',NULL),
        ('_authority_metadata_user_protected_write_v1(text,uuid,timestamptz)','9476b6eb07eb26c0347f4ee470ffec0295248e52e672fd6160fdb61eb17f2dfb','plpgsql','v',false,'jsonb','p_op,p_nonce,p_decision'),
        ('_authority_metadata_user_retention_compile_v1(jsonb,integer)','8e527ccd9544a9fc1a49e66e799f8571ca19b70878df230520f09b738f0343aa','plpgsql','v',false,'jsonb','p_desired,p_work'),
        ('_authority_metadata_user_retention_plan_v1(jsonb,jsonb,jsonb,jsonb,text,jsonb,jsonb,integer)','bc9ba49c0c0241bc862323d8e2ef13bf60ca9358ec39fd6f6e9b8ee8fe0fefac','plpgsql','i',false,'jsonb','p_index,p_catalog,p_outputs,p_old_outputs,p_root_type,p_old,p_new,p_work'),
        ('_authority_metadata_user_retention_prepare_v1(integer,integer,integer)','3f9f45f298bb616ef4fe8bc832539eb7a670698cc8f26535177003f89df90014','plpgsql','v',false,'jsonb','p_rows,p_reads,p_work'),
        ('_authority_metadata_user_target_hold_v1(text,text,integer,integer)','6f74069aa41e99c6562cae6af27134b418cf4c62a388c31fad523ab0ec959b0c','plpgsql','v',false,'jsonb','p_actor_type,p_actor_id,p_rows,p_reads'),
        ('_authority_metadata_user_target_v1(text,text,text,jsonb,jsonb,text,text,integer,integer)','44c93baa24e038f4851d9ab943e1f89ba072f1e38b3438b83da86bcf507f1a56','plpgsql','v',false,'jsonb','p_id,p_xmin,p_ctid,p_old,p_memberships,p_actor_type,p_actor_id,p_rows,p_reads'),
        ('_authority_metadata_user_trigger_v1(oid,text,text,jsonb,jsonb,text,text)','e3b014dee3fb4e0ef31809d9ab7f70772b9079bda4bcd7e2b6c539dbc4662d36','plpgsql','v',false,'jsonb','p_rel,p_name,p_timing,p_old,p_new,p_xmin,p_ctid'),
        ('_authority_metadata_user_write_acl_v1(jsonb,boolean)','8b7ca5f72127039c83bcf26667da160d7c7a518337419db1c0d9108f29264b7b','plpgsql','v',false,'oid','p_saved,p_require_enrollment'),
        ('_authority_user_access_labels_operation_create_v1(text,timestamptz,text,text,bytea,text,text,text)','c4dca4fa51cad40a5625406c7d394858b71fd4a03507053931f8df7abcea4c3c','plpgsql','v',false,'void','p_id,p_created_at,p_user_id,p_account_id,p_metadata,p_actor_type,p_actor_id,p_display_name'),
        ('_authority_user_access_labels_operation_guard_v1()','f54eba9554e36977dfb767d8c3113bd5e09194ec0546e33ba9f5540b56b6f5c9','plpgsql','v',false,'trigger',NULL),
        ('authority_metadata_user_apply_v1(text,uuid,timestamptz,integer,integer,integer)','0edcb455fa513aeb2c08c31d65264c97c896ba77d32c66d2b97896882c5145a5','plpgsql','v',true,'jsonb','p_op,p_nonce,p_decision,p_rows,p_reads,p_work'),
        ('authority_metadata_user_complete_v1(text,uuid,timestamptz,bytea)','93bb0e84a56f023a55225a560530fbe6d5ea418c16b3273442db69577feaee66','plpgsql','v',true,'kaname.operations','p_op,p_nonce,p_decision,p_response'),
        ('authority_metadata_user_finalize_v1(text)','ff8aa07d3c8f01cb20428ab0d708818be2a0985e7d4a088689b82574a12a942c','plpgsql','v',true,'void','p_user_id'),
        ('authority_metadata_user_prepare_v1(text,text,text,jsonb,jsonb,jsonb,text,text,jsonb,integer,integer,integer)','0e8b42c35b8b971968a51a65ca5f065d20234565d1fb07c43044ac7f6c1819eb','plpgsql','v',true,'TABLE(used_rows integer, used_reads integer, used_work integer)','p_id,p_xmin,p_ctid,p_old,p_memberships,p_patch,p_actor_type,p_actor_id,p_policy_expected,p_rows,p_reads,p_work,used_rows,used_reads,used_work'),
        ('authority_metadata_user_reserve_v1(text,timestamptz,bytea,text,text,text,text,text,jsonb,integer,integer,integer)','06dce9b535cb7fa3b097d5d353c142547422e4671c00cd323a794d1b3b51658d','plpgsql','v',true,'jsonb','p_op,p_created,p_metadata,p_account,p_actor_type,p_actor_id,p_display,p_audit,p_desired,p_rows,p_reads,p_work'),
        ('authority_metadata_user_retention_inputs_v1(text,text,integer,integer,integer)','13ab4c53af8a3fe9a1c3b6a93357915b67f39bd26f896585177c6488445cfd7b','plpgsql','v',true,'jsonb','p_actor_type,p_actor_id,p_rows,p_reads,p_work'),
        ('authority_user_access_labels_operation_create_v1(text,timestamptz,text,text,bytea,text,text,text)','c807513b9d0bdf5230781bc44a5be84d3a48b5569c4ce8bf8754d70ac9c2bfef','plpgsql','v',true,'void','p_id,p_created_at,p_user_id,p_account_id,p_metadata,p_actor_type,p_actor_id,p_display_name'),
        ('authority_metadata_user_access_label_ready_v1()','9886259fc2bb278e7bae5123f5df0ae56ddf4f1bb8220ad8e2edb03e71a98ddd','plpgsql','s',true,'boolean',NULL)
    ) expected(signature,digest,lang,volatility,definer,result_type,args) LOOP
        fn:=to_regprocedure('kaname.'||entry.signature);
        exported:=left(entry.signature,1)<>'_';
        IF NOT EXISTS(SELECT FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
            WHERE p.oid=fn AND p.proowner=owner_oid AND p.prokind='f' AND p.prosecdef=entry.definer
                AND p.provolatile::text=entry.volatility AND l.lanname=entry.lang
                AND NOT (p.proisstrict OR p.proleakproof) AND p.proparallel='u'
                AND p.pronargdefaults=0 AND p.provariadic=0 AND p.prosupport=0 AND p.protrftypes IS NULL
                AND p.prosqlbody IS NULL AND p.probin IS NULL AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
                AND p.proargnames IS NOT DISTINCT FROM string_to_array(entry.args,',')
                AND pg_get_function_result(p.oid)=entry.result_type
                AND CASE WHEN entry.result_type LIKE 'TABLE(%' THEN
                    p.proretset AND p.prorettype='record'::regtype AND
                    p.proargmodes::text[]=array_fill('i'::text,ARRAY[p.pronargs::integer])||ARRAY['t','t','t']
                    ELSE NOT p.proretset AND p.proargmodes IS NULL AND p.proallargtypes IS NULL END
                AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=entry.digest
                AND NOT EXISTS(SELECT FROM pg_catalog.pg_proc alt WHERE alt.pronamespace=p.pronamespace
                    AND alt.proname=p.proname AND alt.oid<>p.oid)
                AND NOT EXISTS(SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
                    WHERE a.grantee<>owner_oid AND (NOT exported OR NOT p_installed OR a.grantee<>p_executor
                        OR a.grantor<>owner_oid OR a.privilege_type<>'EXECUTE' OR a.is_grantable))
                AND (NOT (exported AND p_installed) OR has_function_privilege(p_executor,p.oid,'EXECUTE'))) THEN
            RETURN NULL;
        END IF;
        IF exported THEN exports:=array_append(exports,fn); END IF;
    END LOOP;
    -- Недопустима дополнительная вызываемая обёртка под именем семейства.
    IF EXISTS(SELECT FROM pg_catalog.pg_proc p CROSS JOIN LATERAL
        aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        WHERE p.pronamespace='kaname'::regnamespace AND a.grantee<>owner_oid AND p.oid<>ALL(exports::oid[])
            AND (starts_with(p.proname::text,'authority_metadata_user_') OR starts_with(p.proname::text,'_authority_metadata_user_')
                OR p.proname IN ('authority_user_access_labels_operation_create_v1','_authority_user_access_labels_operation_create_v1',
                    '_authority_user_access_labels_operation_guard_v1'))) THEN RETURN NULL; END IF;
    RETURN exports;
END;
$exports$;

CREATE FUNCTION kaname.authority_metadata_user_install_v1(p_runtime regrole,p_executor regrole,p_enable boolean)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $install$
DECLARE seat name; fn regprocedure; exports regprocedure[];
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    PERFORM kaname.authority_protocol_drain();
    SELECT e.role_name INTO seat FROM ONLY kaname.authority_role_actor_login e
    JOIN pg_catalog.pg_roles s ON (s.oid,s.rolname)=(e.role_oid,e.role_name)
    JOIN pg_catalog.pg_roles r ON (r.oid,r.rolname)=(e.runtime_oid,e.runtime_name)
    WHERE e.singleton AND e.role_oid=p_executor::oid AND e.runtime_oid=p_runtime::oid FOR UPDATE OF e;
    IF NOT FOUND OR p_enable IS NULL THEN
        RAISE EXCEPTION 'user metadata installation requires the enrolled LOGIN pair' USING ERRCODE='42501';
    END IF;
    IF NOT p_enable THEN
        -- Отзыв доступен и при повреждении тела одной из функций.
        FOR fn IN SELECT p.oid::regprocedure FROM pg_catalog.pg_proc p
            WHERE p.oid IN (
                to_regprocedure('kaname.authority_metadata_user_apply_v1(text,uuid,timestamptz,integer,integer,integer)'),
                to_regprocedure('kaname.authority_metadata_user_complete_v1(text,uuid,timestamptz,bytea)'),
                to_regprocedure('kaname.authority_metadata_user_finalize_v1(text)'),
                to_regprocedure('kaname.authority_metadata_user_prepare_v1(text,text,text,jsonb,jsonb,jsonb,text,text,jsonb,integer,integer,integer)'),
                to_regprocedure('kaname.authority_metadata_user_reserve_v1(text,timestamptz,bytea,text,text,text,text,text,jsonb,integer,integer,integer)'),
                to_regprocedure('kaname.authority_metadata_user_retention_inputs_v1(text,text,integer,integer,integer)'),
                to_regprocedure('kaname.authority_user_access_labels_operation_create_v1(text,timestamptz,text,text,bytea,text,text,text)'),
                to_regprocedure('kaname.authority_metadata_user_access_label_ready_v1()')) LOOP
            EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM %I',fn,seat);
        END LOOP;
        RETURN;
    END IF;
    -- Проверяем поставщика перечня до его вызова с правами владельца.
    IF NOT EXISTS(SELECT FROM pg_catalog.pg_proc p
        WHERE p.oid='kaname._authority_metadata_user_exports_v1(oid,boolean)'::regprocedure
            AND p.proowner=current_user::regrole AND NOT (p.prosecdef OR p.proisstrict OR p.proretset OR p.proleakproof)
            AND p.prorettype='regprocedure[]'::regtype AND p.provolatile='s' AND p.prokind='f'
            AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
            AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
            AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='bb96a2654a9c80fca86ec7e6ec9485d66820fe1ae245aec0f578ad028a421d08'
            AND NOT EXISTS(SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
                WHERE a.grantee<>p.proowner)) THEN
        RAISE EXCEPTION 'user metadata export verifier differs' USING ERRCODE='55000';
    END IF;
    IF kaname._authority_metadata_user_exports_v1(p_executor::oid,true) IS NOT NULL THEN RETURN; END IF;
    exports:=kaname._authority_metadata_user_exports_v1(p_executor::oid,false);
    IF cardinality(exports) IS DISTINCT FROM 8 THEN
        RAISE EXCEPTION 'user metadata installation requires the complete private contract' USING ERRCODE='55000';
    END IF;
    FOREACH fn IN ARRAY exports LOOP EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %I',fn,seat); END LOOP;
    IF kaname._authority_metadata_user_exports_v1(p_executor::oid,true) IS NULL THEN
        RAISE EXCEPTION 'user metadata executor grants differ' USING ERRCODE='55000';
    END IF;
END;
$install$;
-- +goose StatementEnd

-- Снимаем в том числе ALTER DEFAULT PRIVILEGES. Накат не устанавливает capability.
-- +goose StatementBegin
DO $private$
DECLARE item record;
BEGIN
    FOR item IN SELECT p.oid::regprocedure AS fn,a.grantee,r.rolname FROM pg_catalog.pg_proc p
        CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE a.grantee<>p.proowner AND p.oid IN (
            'kaname._authority_metadata_user_exports_v1(oid,boolean)'::regprocedure,
            'kaname.authority_metadata_user_access_label_ready_v1()'::regprocedure,
            'kaname.authority_metadata_user_install_v1(regrole,regrole,boolean)'::regprocedure) LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',item.fn,
            CASE WHEN item.grantee=0 THEN 'PUBLIC' ELSE format('%I',item.rolname) END);
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- Возвращаем существующие фасады к исходной приватности даже при неполной
-- настройке. Блокировка протокола уже удерживается этой миграцией.
-- +goose StatementBegin
DO $revoke$
DECLARE item record;
BEGIN
    FOR item IN SELECT p.oid::regprocedure AS fn,a.grantee,r.rolname FROM pg_catalog.pg_proc p
        CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE a.grantee<>p.proowner
            AND p.oid IN (
                to_regprocedure('kaname.authority_metadata_user_apply_v1(text,uuid,timestamptz,integer,integer,integer)'),
                to_regprocedure('kaname.authority_metadata_user_complete_v1(text,uuid,timestamptz,bytea)'),
                to_regprocedure('kaname.authority_metadata_user_finalize_v1(text)'),
                to_regprocedure('kaname.authority_metadata_user_prepare_v1(text,text,text,jsonb,jsonb,jsonb,text,text,jsonb,integer,integer,integer)'),
                to_regprocedure('kaname.authority_metadata_user_reserve_v1(text,timestamptz,bytea,text,text,text,text,text,jsonb,integer,integer,integer)'),
                to_regprocedure('kaname.authority_metadata_user_retention_inputs_v1(text,text,integer,integer,integer)'),
                to_regprocedure('kaname.authority_user_access_labels_operation_create_v1(text,timestamptz,text,text,bytea,text,text,text)')) LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',item.fn,
            CASE WHEN item.grantee=0 THEN 'PUBLIC' ELSE format('%I',item.rolname) END);
    END LOOP;
END;
$revoke$;
-- +goose StatementEnd
DROP FUNCTION kaname.authority_metadata_user_install_v1(regrole,regrole,boolean);
DROP FUNCTION kaname._authority_metadata_user_exports_v1(oid,boolean);
DROP FUNCTION kaname.authority_metadata_user_access_label_ready_v1();
