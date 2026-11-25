-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Закрытая команда первой проекции apply для одной редакции определения.

-- +goose Up
SELECT kaname.authority_protocol_drain();
LOCK TABLE ONLY kaname.authority_role_access_label_rule IN ACCESS EXCLUSIVE MODE;

-- +goose StatementBegin
DO $check$ BEGIN
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'Нарушена целостность исходного контракта записи' USING ERRCODE='55000';
    END IF;
END $check$;
-- +goose StatementEnd

-- Команда живёт только до конца своего INSERT. Штатный AFTER-триггер
-- проверяет всю заявку, записывает ожидаемую пару и удаляет команду.
CREATE TABLE kaname.authority_initial_apply_command (
    backend integer PRIMARY KEY,
    transaction_id xid8 NOT NULL,
    account_id text NOT NULL,
    project_id text NOT NULL,
    definition_id uuid NOT NULL,
    definition_revision bigint NOT NULL,
    role_id text NOT NULL,
    rule_fp text
);

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_initial_apply_execute_v1() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $execute$
DECLARE
    actual_rules jsonb;
    expected_rules jsonb;
    fingerprint text;
    compiled_definition uuid;
    inserted kaname.authority_role_access_label_rule%ROWTYPE;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF session_user<>current_user OR pg_trigger_depth()<>1
        OR TG_RELID<>'kaname.authority_initial_apply_command'::regclass
        OR (TG_NAME,TG_WHEN,TG_LEVEL,TG_OP)<>('authority_initial_apply_execute','AFTER','ROW','INSERT')
        OR NEW.backend<>pg_backend_pid() OR NEW.transaction_id<>pg_current_xact_id()
        OR NEW.rule_fp IS NOT NULL THEN
        RAISE EXCEPTION 'Недопустимая команда первичной выдачи apply' USING ERRCODE='42501';
    END IF;
    PERFORM kaname._authority_initial_access_label_apply_target_v1(
        NEW.account_id,NEW.project_id,NEW.definition_id,NEW.definition_revision);
    LOCK TABLE ONLY kaname.authority_role_access_label_rule IN ROW EXCLUSIVE MODE;
    IF NOT kaname._authority_initial_apply_storage_v1() THEN
        RAISE EXCEPTION 'Нарушена защита хранилища первичной выдачи apply' USING ERRCODE='42501';
    END IF;
    expected_rules:=jsonb_build_array(jsonb_build_object('module','iam','resources',jsonb_build_array('accessLabel'),
        'verbs',jsonb_build_array('apply'),'resource_names',jsonb_build_array(NEW.definition_id::text)));
    SELECT r.rules INTO actual_rules FROM ONLY kaname.roles r
    WHERE r.id=NEW.role_id AND r.xmin=pg_current_xact_id()::xid AND r.live AND NOT r.is_system AND r.permissions='[]'::jsonb
        AND r.rules=expected_rules AND r.cluster_id IS NULL AND r.owner_module IS NULL
        AND ((NEW.project_id='' AND r.account_id=NEW.account_id AND r.project_id IS NULL)
            OR (NEW.project_id<>'' AND r.account_id IS NULL AND r.project_id=NEW.project_id))
    FOR UPDATE OF r;
    -- UPDATE старой роли также меняет xmin. CREATED в журнале отличает
    -- создание от правки, а время отсекает старую эпоху 32-битного xmin.
    IF NOT FOUND OR NOT EXISTS (SELECT FROM ONLY kaname.resource_journal j
            WHERE j.resource_kind='iam_role' AND j.resource_id=NEW.role_id AND j.event_type='CREATED'
                AND j.xmin=pg_current_xact_id()::xid AND j.created_at>=transaction_timestamp())
        OR EXISTS (SELECT FROM ONLY kaname.authority_initial_access_label_apply_issuance i
            WHERE i.definition_id=NEW.definition_id OR i.role_id=NEW.role_id)
        OR EXISTS (SELECT FROM ONLY kaname.authority_role_access_label_rule p
            WHERE p.role_id=NEW.role_id OR p.definition_id=NEW.definition_id)
        OR EXISTS (SELECT FROM ONLY kaname.access_bindings b WHERE b.role_id=NEW.role_id) THEN
        RAISE EXCEPTION 'Для первичной выдачи требуется отдельная свободная роль с одним правилом apply'
            USING ERRCODE='42501';
    END IF;
    SELECT c.rule_fp,c.definition_id INTO STRICT fingerprint,compiled_definition
    FROM kaname.authority_access_label_role_compile_v1(actual_rules) c;
    IF compiled_definition IS DISTINCT FROM NEW.definition_id OR fingerprint IS NULL THEN
        RAISE EXCEPTION 'Вычисленная проекция apply расходится с определением' USING ERRCODE='42501';
    END IF;

    UPDATE ONLY kaname.authority_initial_apply_command SET rule_fp=fingerprint
    WHERE backend=NEW.backend AND transaction_id=NEW.transaction_id AND rule_fp IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION 'Команда первичной выдачи уже выполнена' USING ERRCODE='42501'; END IF;
    INSERT INTO kaname.authority_role_access_label_rule(role_id,rule_fp,definition_id)
    VALUES(NEW.role_id,fingerprint,compiled_definition) RETURNING * INTO STRICT inserted;
    IF (inserted.role_id,inserted.rule_fp,inserted.definition_id)
        IS DISTINCT FROM (NEW.role_id,fingerprint,compiled_definition) THEN
        RAISE EXCEPTION 'Записанная проекция apply изменилась' USING ERRCODE='40001';
    END IF;
    DELETE FROM ONLY kaname.authority_initial_apply_command
    WHERE backend=NEW.backend AND transaction_id=NEW.transaction_id AND rule_fp=fingerprint;
    IF NOT FOUND THEN RAISE EXCEPTION 'Нарушено завершение первичной выдачи' USING ERRCODE='40001'; END IF;
    RETURN NULL;
END;
$execute$;
-- +goose StatementEnd

-- После удаления короткоживущей команды PostgreSQL сохраняет её NEW
-- для отложенного триггера. Проверка связывает проекцию с результатом
-- всей установки и не позволяет зафиксировать одиночный вызов проектора.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_initial_apply_complete_v1() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $complete$
DECLARE recipient text; expected_rules jsonb;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF current_user<>session_user OR TG_RELID<>'kaname.authority_initial_apply_command'::regclass
        OR (TG_NAME,TG_WHEN,TG_LEVEL,TG_OP)<>('authority_initial_apply_complete','AFTER','ROW','INSERT')
        OR NEW.backend<>pg_backend_pid() OR NEW.transaction_id<>pg_current_xact_id()
        OR NEW.rule_fp IS NOT NULL THEN
        RAISE EXCEPTION 'Изменился источник завершения первичной выдачи apply' USING ERRCODE='42501';
    END IF;
    recipient:=kaname._authority_initial_access_label_apply_target_v1(
        NEW.account_id,NEW.project_id,NEW.definition_id,NEW.definition_revision);
    expected_rules:=jsonb_build_array(jsonb_build_object('module','iam','resources',jsonb_build_array('accessLabel'),
        'verbs',jsonb_build_array('apply'),'resource_names',jsonb_build_array(NEW.definition_id::text)));

    IF NOT EXISTS (
        SELECT FROM ONLY kaname.authority_initial_access_label_apply_issuance i
        JOIN ONLY kaname.roles r ON r.id=i.role_id
        CROSS JOIN LATERAL kaname.authority_access_label_role_compile_v1(r.rules) compiled
        JOIN ONLY kaname.authority_role_access_label_rule p ON p.role_id=r.id
            AND (p.rule_fp,p.definition_id)=(compiled.rule_fp,compiled.definition_id)
        JOIN ONLY kaname.access_bindings b ON (b.id,b.role_id)=(i.binding_id,r.id)
        JOIN ONLY kaname.access_binding_subjects s ON (s.binding_id,s.subject_type,s.subject_id)=(b.id,'user',recipient)
            AND (s.resource_type,s.resource_id)=(b.resource_type,b.resource_id)
        WHERE (i.definition_id,i.definition_revision,i.account_id,i.project_id,i.role_id,i.recipient_user_id)
            =(NEW.definition_id,NEW.definition_revision,NEW.account_id,NEW.project_id,NEW.role_id,recipient)
            AND i.xmin=NEW.transaction_id::xid AND b.xmin=NEW.transaction_id::xid
            AND p.definition_id=i.definition_id AND p.xmin=NEW.transaction_id::xid
            AND r.live AND r.cluster_id IS NULL AND r.owner_module IS NULL
            AND r.permissions='[]'::jsonb AND r.rules=expected_rules
            AND (b.subject_type,b.subject_id)=('user',recipient)
            AND b.status='ACTIVE' AND b.grant_capability_version=1 AND b.delegation_id IS NULL
            AND NOT b.is_system AND NOT b.deletion_protection AND b.granted_relation='' AND b.expires_at IS NULL
            AND b.revoked_at IS NULL AND b.target='{"allInScope":true}'::jsonb AND b.target_digest='all'
            AND ((i.project_id='' AND r.account_id=i.account_id AND r.project_id IS NULL
                    AND (b.scope,b.resource_type,b.resource_id)=(2,'account',i.account_id))
                OR (i.project_id<>'' AND r.account_id IS NULL AND r.project_id=i.project_id
                    AND (b.scope,b.resource_type,b.resource_id)=(3,'project',i.project_id)))
            AND (SELECT count(*) FROM ONLY kaname.authority_role_access_label_rule q WHERE q.role_id=r.id)=1
            AND (SELECT count(*) FROM ONLY kaname.access_bindings q WHERE q.role_id=r.id)=1
            AND (SELECT count(*) FROM ONLY kaname.access_binding_subjects q WHERE q.binding_id=b.id)=1
    ) THEN
        RAISE EXCEPTION 'Не завершена первичная выдача apply владельцу: роль, проекция, привязка или квитанция расходятся'
            USING ERRCODE='42501';
    END IF;
    RETURN NULL;
END;
$complete$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_initial_apply_storage_v1() RETURNS boolean
LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $storage$
    WITH relations(id) AS (VALUES
        ('kaname.authority_role_access_label_rule'::regclass),
        ('kaname.authority_initial_apply_command'::regclass)
    ), expected(relid,trigger_name,trigger_type,fn,new_table,deferred) AS (VALUES
        ('kaname.authority_role_access_label_rule'::regclass,'authority_role_access_label_rule_closed',62,
            'kaname.authority_role_access_label_rule_closed_v1()'::regprocedure,NULL::text,false),
        ('kaname.authority_role_access_label_rule'::regclass,'authority_initial_apply_effect',4,
            'kaname.authority_role_access_label_rule_closed_v1()'::regprocedure,'initial_apply_effect',false),
        ('kaname.authority_initial_apply_command'::regclass,'authority_initial_apply_execute',5,
            'kaname._authority_initial_apply_execute_v1()'::regprocedure,NULL::text,false),
        ('kaname.authority_initial_apply_command'::regclass,'authority_initial_apply_complete',5,
            'kaname._authority_initial_apply_complete_v1()'::regprocedure,NULL::text,true)
    )
    SELECT NOT EXISTS (
        SELECT FROM relations r JOIN pg_catalog.pg_class c ON c.oid=r.id
        WHERE c.relowner<>current_user::regrole OR c.relkind<>'r' OR c.relpersistence<>'p'
            OR c.relhasrules OR c.relrowsecurity OR c.relhassubclass OR c.relispartition
            OR EXISTS (SELECT FROM pg_catalog.aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
                WHERE a.grantee<>c.relowner)
            OR EXISTS (SELECT FROM pg_catalog.pg_attribute v CROSS JOIN LATERAL aclexplode(v.attacl) a
                WHERE v.attrelid=c.oid AND a.grantee<>c.relowner)
    ) AND NOT EXISTS (
        SELECT FROM pg_catalog.pg_trigger t WHERE t.tgrelid IN (SELECT id FROM relations)
            AND NOT t.tgisinternal AND NOT EXISTS (SELECT FROM expected e
                WHERE (e.relid,e.trigger_name)=(t.tgrelid,t.tgname::text))
    ) AND NOT EXISTS (
        SELECT FROM expected e WHERE NOT EXISTS (
            SELECT FROM pg_catalog.pg_trigger t WHERE (t.tgrelid,t.tgname::text)=(e.relid,e.trigger_name)
                AND t.tgtype=e.trigger_type AND t.tgfoid=e.fn AND NOT t.tgisinternal
                AND t.tgenabled='O' AND t.tgqual IS NULL AND t.tgnargs=0 AND t.tgattr=''::int2vector
                AND (t.tgdeferrable,t.tginitdeferred)=(e.deferred,e.deferred)
                AND ((NOT e.deferred AND t.tgconstraint=0) OR (e.deferred AND EXISTS (
                    SELECT FROM pg_catalog.pg_constraint k WHERE k.oid=t.tgconstraint AND k.contype='t'
                        AND k.conrelid=t.tgrelid AND k.conname=t.tgname AND k.condeferrable AND k.condeferred)))
                AND t.tgnewtable::text IS NOT DISTINCT FROM e.new_table AND t.tgoldtable IS NULL
        )
    )
$storage$;
-- +goose StatementEnd

CREATE TRIGGER authority_initial_apply_execute
    AFTER INSERT ON kaname.authority_initial_apply_command
    FOR EACH ROW EXECUTE FUNCTION kaname._authority_initial_apply_execute_v1();

CREATE CONSTRAINT TRIGGER authority_initial_apply_complete
    AFTER INSERT ON kaname.authority_initial_apply_command
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION kaname._authority_initial_apply_complete_v1();

CREATE TRIGGER authority_initial_apply_effect
    AFTER INSERT ON kaname.authority_role_access_label_rule
    REFERENCING NEW TABLE AS initial_apply_effect
    FOR EACH STATEMENT EXECUTE FUNCTION kaname.authority_role_access_label_rule_closed_v1();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_initial_access_label_apply_project_v1(
    p_account text,p_project text,p_definition uuid,p_revision bigint,p_role text
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $project$
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF current_user<>session_user OR pg_trigger_depth()<>0 OR coalesce(p_role,'')='' THEN
        RAISE EXCEPTION 'Первичная выдача требует учётную запись владельца миграций и роль'
            USING ERRCODE='42501';
    END IF;
    LOCK TABLE ONLY kaname.authority_initial_apply_command IN ROW EXCLUSIVE MODE;
    IF NOT kaname._authority_initial_apply_storage_v1() THEN
        RAISE EXCEPTION 'Нарушена защита хранилища первичной выдачи apply' USING ERRCODE='42501';
    END IF;
    INSERT INTO kaname.authority_initial_apply_command(
        backend,transaction_id,account_id,project_id,definition_id,definition_revision,role_id)
    VALUES(pg_backend_pid(),pg_current_xact_id(),p_account,p_project,p_definition,p_revision,p_role);
    IF EXISTS (SELECT FROM ONLY kaname.authority_initial_apply_command WHERE backend=pg_backend_pid()) THEN
        RAISE EXCEPTION 'Команда первичной выдачи не завершена' USING ERRCODE='40001';
    END IF;
END;
$project$;
-- +goose StatementEnd


-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure; grantee record;
BEGIN
    FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_class c
        CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
        WHERE c.oid='kaname.authority_initial_apply_command'::regclass AND a.grantee<>c.relowner LOOP
        EXECUTE format('REVOKE ALL ON kaname.authority_initial_apply_command FROM %s',
            CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
    END LOOP;
    FOREACH fn IN ARRAY ARRAY[
        'kaname._authority_initial_apply_execute_v1()'::regprocedure,
        'kaname._authority_initial_apply_complete_v1()'::regprocedure,
        'kaname._authority_initial_apply_storage_v1()'::regprocedure,
        'kaname._authority_initial_access_label_apply_project_v1(text,text,uuid,bigint,text)'::regprocedure
    ] LOOP
        FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
            WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
                CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
        END LOOP;
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $repin$
DECLARE item record; fn regprocedure; prior_body text; body text; definition text; pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('authority_role_access_label_rule_closed_v1()','9215a52e70f6989a1aa6ebc8f4d5cdc05cc78799c49688eb641eb475ac5dce67','80f30e2f6b70292b63a84cc5a787697e36af999c8e9d96f8a814a1c16b136250',
   $pairs$[
 [
  "DECLARE program jsonb;",
  "DECLARE program jsonb; command record;"
 ],
 [
  "BEGIN\n    IF TG_TABLE_SCHEMA=",
  "BEGIN\n    -- Обе фазы вложенного INSERT сверяются с командой текущего backend.\n    -- При обычной записи writer команда отсутствует; его прежний допуск\n    -- проверяется BEFORE, а весь результирующий набор — основным writer.\n    IF TG_RELID='kaname.authority_role_access_label_rule'::regclass AND TG_LEVEL='STATEMENT' AND TG_OP='INSERT' THEN\n        IF current_user=session_user AND pg_trigger_depth()=2 THEN\n            SELECT c.* INTO command FROM ONLY kaname.authority_initial_apply_command c\n            WHERE c.backend=pg_backend_pid() AND c.transaction_id=pg_current_xact_id_if_assigned()\n                AND c.rule_fp IS NOT NULL;\n            IF FOUND THEN\n                PERFORM kaname.authority_protocol_require_owner();\n                IF TG_NAME='authority_role_access_label_rule_closed' AND TG_WHEN='BEFORE' THEN\n                    RETURN NULL;\n                ELSIF TG_NAME='authority_initial_apply_effect' AND TG_WHEN='AFTER' THEN\n                    IF (SELECT count(*) FROM initial_apply_effect)<>1 OR NOT EXISTS (\n                        SELECT FROM initial_apply_effect r WHERE (r.role_id,r.rule_fp,r.definition_id)\n                            =(command.role_id,command.rule_fp,command.definition_id)\n                    ) THEN\n                        RAISE EXCEPTION 'Состав строк первичной проекции apply изменился' USING ERRCODE='40001';\n                    END IF;\n                    RETURN NULL;\n                END IF;\n            END IF;\n        END IF;\n        IF TG_NAME='authority_initial_apply_effect' AND TG_WHEN='AFTER' THEN RETURN NULL; END IF;\n    END IF;\n    IF TG_TABLE_SCHEMA="
 ]
]$pairs$::jsonb),
  ('authority_access_label_role_projection_apply_v1(jsonb,text,text)','959fe69a787f20a99919ec47b666cfdf9bf074c01a4ac203b66459fae5da7940','6193f5886bfd719ee6cc16d364e8212a0712ac08b93b1f63fd73e46c464ee8f6',
   $pairs$[
 [
  "        -- В коротком интервале записи разрешён только штатный сторож таблицы.\n        -- Внешний триггер или правило не может исполниться под этим режимом.\n        IF NOT EXISTS (\n            SELECT 1 FROM pg_catalog.pg_class c\n            WHERE c.oid='kaname.authority_role_access_label_rule'::regclass\n              AND c.relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)\n              AND c.relkind='r' AND c.relpersistence='p'\n              AND NOT (c.relhasrules OR c.relrowsecurity)\n              AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(coalesce(c.relacl,pg_catalog.acldefault('r',c.relowner))) a\n                              WHERE a.grantee<>c.relowner)\n              AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute v CROSS JOIN LATERAL pg_catalog.aclexplode(v.attacl) a\n                              WHERE v.attrelid=c.oid AND a.grantee<>c.relowner)\n              AND (SELECT count(*) FROM pg_catalog.pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal)=1\n              AND EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t\n                          WHERE t.tgrelid=c.oid AND NOT t.tgisinternal\n                            AND t.tgname='authority_role_access_label_rule_closed' AND t.tgtype=62\n                            AND t.tgenabled='O' AND t.tgqual IS NULL\n                            AND t.tgfoid='kaname.authority_role_access_label_rule_closed_v1()'::regprocedure)\n        )",
  "        IF NOT kaname._authority_initial_apply_storage_v1()"
 ]
]$pairs$::jsonb),
  ('_authority_crud_storage_v3()','ef90143402897fd414dbbd8d5645f585ed9a8b93bdc6d69da8e9c309555824ee','682e0939504415f3796203497d1e747c8e452e63a522bac55de1978cdae815f4',
   $pairs$[
 [
  "9215a52e70f6989a1aa6ebc8f4d5cdc05cc78799c49688eb641eb475ac5dce67",
  "80f30e2f6b70292b63a84cc5a787697e36af999c8e9d96f8a814a1c16b136250"
 ],
 [
  "959fe69a787f20a99919ec47b666cfdf9bf074c01a4ac203b66459fae5da7940",
  "6193f5886bfd719ee6cc16d364e8212a0712ac08b93b1f63fd73e46c464ee8f6"
 ],
 [
  " ('authority_role_access_label_rule_closed_v1()','80f30e2f6b70292b63a84cc5a787697e36af999c8e9d96f8a814a1c16b136250',false,'v',true,'private'),",
  " ('authority_role_access_label_rule_closed_v1()','80f30e2f6b70292b63a84cc5a787697e36af999c8e9d96f8a814a1c16b136250',false,'v',true,'private'),\n ('_authority_initial_apply_execute_v1()','3d37cadf2e8018b161786cca08c06a76f436660a88d62f6ef1fa63430fc9943e',false,'v',true,'private'),\n ('_authority_initial_apply_complete_v1()','091d940f64e9df669a358c70614019093842d2bbf90d5248785fb94433c53262',false,'v',true,'private'),\n ('_authority_initial_apply_storage_v1()','7cc81537848eeaba9b8556929aea88af64c54172e0d4b5cb0872a5c9885be3c2',false,'s',true,'private'),\n ('_authority_initial_access_label_apply_project_v1(text,text,uuid,bigint,text)','d2cba7888813b2c24aa57e552c9612f2bcce18dee15fa030898fa436449190a5',false,'v',true,'private'),\n ('_authority_initial_access_label_apply_target_v1(text,text,uuid,bigint)','6c3c70cd5c748d4fe7e8a4e2f5f1cfdf767d60e273f59de678dbb9f3148acc5a',false,'v',true,'private'),"
 ],
 [
  " RETURN kaname._authority_group_add_storage_v3() AND",
  " RETURN kaname._authority_initial_apply_storage_v1() AND kaname._authority_group_add_storage_v3() AND"
 ]
]$pairs$::jsonb),
  ('_authority_full_contract_storage_v3()','3a0f261127fe44e479df420fea71603f5f1131f4b08a87219d3282e70e0b1145','a59db331e044a8960693abd760c379f0de01cb80c02a317496e0eac35d28dc3f',
   $pairs$[
 [
  "ef90143402897fd414dbbd8d5645f585ed9a8b93bdc6d69da8e9c309555824ee",
  "682e0939504415f3796203497d1e747c8e452e63a522bac55de1978cdae815f4"
 ]
]$pairs$::jsonb),
  ('authority_metadata_service_account_access_label_ready_v1()','65a6271c581e9577a6065f4a1355e0376b1dbdef7fc63822d7aacead13fe8805','0af65177bbfcad5e8d4a54502d922ad934de0141b1f63116130377fd184218ae',
   $pairs$[
 [
  "ef90143402897fd414dbbd8d5645f585ed9a8b93bdc6d69da8e9c309555824ee",
  "682e0939504415f3796203497d1e747c8e452e63a522bac55de1978cdae815f4"
 ],
 [
  "3a0f261127fe44e479df420fea71603f5f1131f4b08a87219d3282e70e0b1145",
  "a59db331e044a8960693abd760c379f0de01cb80c02a317496e0eac35d28dc3f"
 ]
]$pairs$::jsonb)
 ) AS pins(signature,before_hash,after_hash,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT prior_body,definition FROM pg_catalog.pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(prior_body,'UTF8')),'hex') IS DISTINCT FROM item.before_hash THEN
   RAISE EXCEPTION 'Исходное тело функции % изменилось',item.signature USING ERRCODE='55000';
  END IF;
  body:=prior_body;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF length(body)-length(replace(body,pair->>0,''))<>length(pair->>0) THEN
    RAISE EXCEPTION 'Фрагмент тела функции % не уникален',item.signature USING ERRCODE='55000';
   END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.after_hash
   OR length(definition)-length(replace(definition,prior_body,''))<>length(prior_body) THEN
   RAISE EXCEPTION 'Расчётный образ функции % изменился',item.signature USING ERRCODE='55000';
  END IF;
  EXECUTE replace(definition,prior_body,body);
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
     IS DISTINCT FROM item.after_hash THEN
   RAISE EXCEPTION 'Установленное тело функции % изменилось',item.signature USING ERRCODE='55000';
  END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'Нарушена целостность контракта записи' USING ERRCODE='55000';
 END IF;
END;
$repin$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
LOCK TABLE ONLY kaname.authority_role_access_label_rule IN ACCESS EXCLUSIVE MODE;

-- +goose StatementBegin
DO $check$ BEGIN
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'Нарушена целостность исходного контракта записи' USING ERRCODE='55000';
    END IF;
END $check$;
-- +goose StatementEnd

LOCK TABLE ONLY kaname.authority_initial_apply_command IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $empty$ BEGIN
    IF EXISTS (SELECT FROM ONLY kaname.authority_initial_apply_command) THEN
        RAISE EXCEPTION 'Не завершена первичная выдача apply' USING ERRCODE='55000';
    END IF;
END $empty$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $repin$
DECLARE item record; fn regprocedure; prior_body text; body text; definition text; pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('authority_metadata_service_account_access_label_ready_v1()','0af65177bbfcad5e8d4a54502d922ad934de0141b1f63116130377fd184218ae','65a6271c581e9577a6065f4a1355e0376b1dbdef7fc63822d7aacead13fe8805',
   $pairs$[
 [
  "a59db331e044a8960693abd760c379f0de01cb80c02a317496e0eac35d28dc3f",
  "3a0f261127fe44e479df420fea71603f5f1131f4b08a87219d3282e70e0b1145"
 ],
 [
  "682e0939504415f3796203497d1e747c8e452e63a522bac55de1978cdae815f4",
  "ef90143402897fd414dbbd8d5645f585ed9a8b93bdc6d69da8e9c309555824ee"
 ]
]$pairs$::jsonb),
  ('_authority_full_contract_storage_v3()','a59db331e044a8960693abd760c379f0de01cb80c02a317496e0eac35d28dc3f','3a0f261127fe44e479df420fea71603f5f1131f4b08a87219d3282e70e0b1145',
   $pairs$[
 [
  "682e0939504415f3796203497d1e747c8e452e63a522bac55de1978cdae815f4",
  "ef90143402897fd414dbbd8d5645f585ed9a8b93bdc6d69da8e9c309555824ee"
 ]
]$pairs$::jsonb),
  ('_authority_crud_storage_v3()','682e0939504415f3796203497d1e747c8e452e63a522bac55de1978cdae815f4','ef90143402897fd414dbbd8d5645f585ed9a8b93bdc6d69da8e9c309555824ee',
   $pairs$[
 [
  " RETURN kaname._authority_initial_apply_storage_v1() AND kaname._authority_group_add_storage_v3() AND",
  " RETURN kaname._authority_group_add_storage_v3() AND"
 ],
 [
  " ('authority_role_access_label_rule_closed_v1()','80f30e2f6b70292b63a84cc5a787697e36af999c8e9d96f8a814a1c16b136250',false,'v',true,'private'),\n ('_authority_initial_apply_execute_v1()','3d37cadf2e8018b161786cca08c06a76f436660a88d62f6ef1fa63430fc9943e',false,'v',true,'private'),\n ('_authority_initial_apply_complete_v1()','091d940f64e9df669a358c70614019093842d2bbf90d5248785fb94433c53262',false,'v',true,'private'),\n ('_authority_initial_apply_storage_v1()','7cc81537848eeaba9b8556929aea88af64c54172e0d4b5cb0872a5c9885be3c2',false,'s',true,'private'),\n ('_authority_initial_access_label_apply_project_v1(text,text,uuid,bigint,text)','d2cba7888813b2c24aa57e552c9612f2bcce18dee15fa030898fa436449190a5',false,'v',true,'private'),\n ('_authority_initial_access_label_apply_target_v1(text,text,uuid,bigint)','6c3c70cd5c748d4fe7e8a4e2f5f1cfdf767d60e273f59de678dbb9f3148acc5a',false,'v',true,'private'),",
  " ('authority_role_access_label_rule_closed_v1()','80f30e2f6b70292b63a84cc5a787697e36af999c8e9d96f8a814a1c16b136250',false,'v',true,'private'),"
 ],
 [
  "6193f5886bfd719ee6cc16d364e8212a0712ac08b93b1f63fd73e46c464ee8f6",
  "959fe69a787f20a99919ec47b666cfdf9bf074c01a4ac203b66459fae5da7940"
 ],
 [
  "80f30e2f6b70292b63a84cc5a787697e36af999c8e9d96f8a814a1c16b136250",
  "9215a52e70f6989a1aa6ebc8f4d5cdc05cc78799c49688eb641eb475ac5dce67"
 ]
]$pairs$::jsonb),
  ('authority_access_label_role_projection_apply_v1(jsonb,text,text)','6193f5886bfd719ee6cc16d364e8212a0712ac08b93b1f63fd73e46c464ee8f6','959fe69a787f20a99919ec47b666cfdf9bf074c01a4ac203b66459fae5da7940',
   $pairs$[
 [
  "        IF NOT kaname._authority_initial_apply_storage_v1()",
  "        -- В коротком интервале записи разрешён только штатный сторож таблицы.\n        -- Внешний триггер или правило не может исполниться под этим режимом.\n        IF NOT EXISTS (\n            SELECT 1 FROM pg_catalog.pg_class c\n            WHERE c.oid='kaname.authority_role_access_label_rule'::regclass\n              AND c.relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)\n              AND c.relkind='r' AND c.relpersistence='p'\n              AND NOT (c.relhasrules OR c.relrowsecurity)\n              AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(coalesce(c.relacl,pg_catalog.acldefault('r',c.relowner))) a\n                              WHERE a.grantee<>c.relowner)\n              AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute v CROSS JOIN LATERAL pg_catalog.aclexplode(v.attacl) a\n                              WHERE v.attrelid=c.oid AND a.grantee<>c.relowner)\n              AND (SELECT count(*) FROM pg_catalog.pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal)=1\n              AND EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t\n                          WHERE t.tgrelid=c.oid AND NOT t.tgisinternal\n                            AND t.tgname='authority_role_access_label_rule_closed' AND t.tgtype=62\n                            AND t.tgenabled='O' AND t.tgqual IS NULL\n                            AND t.tgfoid='kaname.authority_role_access_label_rule_closed_v1()'::regprocedure)\n        )"
 ]
]$pairs$::jsonb),
  ('authority_role_access_label_rule_closed_v1()','80f30e2f6b70292b63a84cc5a787697e36af999c8e9d96f8a814a1c16b136250','9215a52e70f6989a1aa6ebc8f4d5cdc05cc78799c49688eb641eb475ac5dce67',
   $pairs$[
 [
  "BEGIN\n    -- Обе фазы вложенного INSERT сверяются с командой текущего backend.\n    -- При обычной записи writer команда отсутствует; его прежний допуск\n    -- проверяется BEFORE, а весь результирующий набор — основным writer.\n    IF TG_RELID='kaname.authority_role_access_label_rule'::regclass AND TG_LEVEL='STATEMENT' AND TG_OP='INSERT' THEN\n        IF current_user=session_user AND pg_trigger_depth()=2 THEN\n            SELECT c.* INTO command FROM ONLY kaname.authority_initial_apply_command c\n            WHERE c.backend=pg_backend_pid() AND c.transaction_id=pg_current_xact_id_if_assigned()\n                AND c.rule_fp IS NOT NULL;\n            IF FOUND THEN\n                PERFORM kaname.authority_protocol_require_owner();\n                IF TG_NAME='authority_role_access_label_rule_closed' AND TG_WHEN='BEFORE' THEN\n                    RETURN NULL;\n                ELSIF TG_NAME='authority_initial_apply_effect' AND TG_WHEN='AFTER' THEN\n                    IF (SELECT count(*) FROM initial_apply_effect)<>1 OR NOT EXISTS (\n                        SELECT FROM initial_apply_effect r WHERE (r.role_id,r.rule_fp,r.definition_id)\n                            =(command.role_id,command.rule_fp,command.definition_id)\n                    ) THEN\n                        RAISE EXCEPTION 'Состав строк первичной проекции apply изменился' USING ERRCODE='40001';\n                    END IF;\n                    RETURN NULL;\n                END IF;\n            END IF;\n        END IF;\n        IF TG_NAME='authority_initial_apply_effect' AND TG_WHEN='AFTER' THEN RETURN NULL; END IF;\n    END IF;\n    IF TG_TABLE_SCHEMA=",
  "BEGIN\n    IF TG_TABLE_SCHEMA="
 ],
 [
  "DECLARE program jsonb; command record;",
  "DECLARE program jsonb;"
 ]
]$pairs$::jsonb)
 ) AS pins(signature,before_hash,after_hash,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT prior_body,definition FROM pg_catalog.pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(prior_body,'UTF8')),'hex') IS DISTINCT FROM item.before_hash THEN
   RAISE EXCEPTION 'Исходное тело функции % изменилось',item.signature USING ERRCODE='55000';
  END IF;
  body:=prior_body;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF length(body)-length(replace(body,pair->>0,''))<>length(pair->>0) THEN
    RAISE EXCEPTION 'Фрагмент тела функции % не уникален',item.signature USING ERRCODE='55000';
   END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.after_hash
   OR length(definition)-length(replace(definition,prior_body,''))<>length(prior_body) THEN
   RAISE EXCEPTION 'Расчётный образ функции % изменился',item.signature USING ERRCODE='55000';
  END IF;
  EXECUTE replace(definition,prior_body,body);
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
     IS DISTINCT FROM item.after_hash THEN
   RAISE EXCEPTION 'Установленное тело функции % изменилось',item.signature USING ERRCODE='55000';
  END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'Нарушена целостность контракта записи' USING ERRCODE='55000';
 END IF;
END;
$repin$;
-- +goose StatementEnd
DROP TRIGGER authority_initial_apply_effect ON kaname.authority_role_access_label_rule;
DROP TRIGGER authority_initial_apply_complete ON kaname.authority_initial_apply_command;
DROP TRIGGER authority_initial_apply_execute ON kaname.authority_initial_apply_command;
DROP FUNCTION kaname._authority_initial_access_label_apply_project_v1(text,text,uuid,bigint,text);
DROP FUNCTION kaname._authority_initial_apply_storage_v1();
DROP FUNCTION kaname._authority_initial_apply_complete_v1();
DROP FUNCTION kaname._authority_initial_apply_execute_v1();
DROP TABLE kaname.authority_initial_apply_command;
