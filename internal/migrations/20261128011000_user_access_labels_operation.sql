-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

ALTER TABLE kaname.operations ADD COLUMN user_access_labels boolean NOT NULL DEFAULT false;

-- Старый reconciler не знает дополнительного поля в публичной Any metadata.
-- Только владелец устанавливает признак при создании pending. Защищённая строка
-- допускает heartbeat и переход в ошибку до установки атомарной записи результата.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_user_access_labels_operation_guard_v1()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $guard$
BEGIN
    IF TG_OP='INSERT' THEN
        PERFORM kaname.authority_protocol_require_owner();
        IF NEW.done OR NEW.error_code IS NOT NULL OR NEW.error_message IS NOT NULL OR NEW.error_details IS NOT NULL
            OR NEW.response_type IS NOT NULL OR NEW.response_data IS NOT NULL THEN
            RAISE EXCEPTION 'protected user operation must start pending' USING ERRCODE='42501';
        END IF;
    ELSIF TG_OP='UPDATE' THEN
        IF OLD.user_access_labels IS DISTINCT FROM NEW.user_access_labels OR OLD.done
            OR ROW(NEW.id, NEW.description, NEW.created_at, NEW.created_by, NEW.principal_type,
                   NEW.principal_id, NEW.principal_display_name, NEW.resource_id, NEW.account_id,
                   NEW.metadata_type, NEW.metadata_data)
                IS DISTINCT FROM
               ROW(OLD.id, OLD.description, OLD.created_at, OLD.created_by, OLD.principal_type,
                   OLD.principal_id, OLD.principal_display_name, OLD.resource_id, OLD.account_id,
                   OLD.metadata_type, OLD.metadata_data) THEN
            RAISE EXCEPTION 'protected user operation identity is immutable' USING ERRCODE='42501';
        END IF;
        IF TG_WHEN='BEFORE' THEN
            -- Старый resolver при наличии User посылает её в MarkDone.
            -- Записываем штатный OutcomeInterrupted и подавляем внешнюю запись
            -- ответа: MarkDone видит ErrAlreadyDone, а весь batch может завершиться.
            UPDATE ONLY kaname.operations SET done=true,modified_at=clock_timestamp(),
                error_code=13,error_message='operation interrupted before completion'
                WHERE id=OLD.id AND NOT done;
            RETURN NULL;
        END IF;
        IF NEW.response_type IS NOT NULL OR NEW.response_data IS NOT NULL
            OR (NEW.done AND coalesce(NEW.error_code,0) NOT BETWEEN 1 AND 16)
            OR (NOT NEW.done AND (NEW.error_code IS NOT NULL OR NEW.error_message IS NOT NULL
                                  OR NEW.error_details IS NOT NULL)) THEN
            RAISE EXCEPTION 'protected user operation requires its owner transition' USING ERRCODE='42501';
        END IF;
    ELSIF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'protected pending user operation cannot be deleted' USING ERRCODE='42501';
    ELSE
        IF current_setting('transaction_isolation') NOT IN ('read committed','read uncommitted') THEN
            RAISE EXCEPTION 'truncating operations requires a current snapshot' USING ERRCODE='25001';
        END IF;
        IF EXISTS(SELECT FROM ONLY kaname.operations WHERE user_access_labels AND NOT done) THEN
            RAISE EXCEPTION 'protected pending user operation prevents truncate' USING ERRCODE='42501';
        END IF;
    END IF;
    RETURN NULL;
END;
$guard$;
-- +goose StatementEnd

-- WHEN оставляет обычные операции вне функции. AFTER проверяет конечную строку
-- после всех BEFORE-триггеров. Уборка терминальных записей остаётся штатной.
CREATE TRIGGER user_access_labels_operation_insert AFTER INSERT ON kaname.operations
    FOR EACH ROW WHEN (NEW.user_access_labels) EXECUTE FUNCTION kaname._authority_user_access_labels_operation_guard_v1();
CREATE TRIGGER user_access_labels_operation_interrupt BEFORE UPDATE ON kaname.operations
    FOR EACH ROW WHEN (OLD.user_access_labels AND NEW.user_access_labels AND NOT OLD.done AND NEW.done
        AND NEW.error_code IS NULL AND NEW.error_message IS NULL AND NEW.error_details IS NULL
        AND NEW.response_type='type.googleapis.com/kaname.cloud.iam.v1.User' AND NEW.response_data IS NOT NULL)
    EXECUTE FUNCTION kaname._authority_user_access_labels_operation_guard_v1();
CREATE TRIGGER user_access_labels_operation_update AFTER UPDATE ON kaname.operations
    FOR EACH ROW WHEN (OLD.user_access_labels OR NEW.user_access_labels) EXECUTE FUNCTION kaname._authority_user_access_labels_operation_guard_v1();
CREATE TRIGGER user_access_labels_operation_delete AFTER DELETE ON kaname.operations
    FOR EACH ROW WHEN (OLD.user_access_labels AND NOT OLD.done) EXECUTE FUNCTION kaname._authority_user_access_labels_operation_guard_v1();
CREATE TRIGGER user_access_labels_operation_truncate BEFORE TRUNCATE ON kaname.operations
    FOR EACH STATEMENT EXECUTE FUNCTION kaname._authority_user_access_labels_operation_guard_v1();
ALTER TABLE kaname.operations ENABLE ALWAYS TRIGGER user_access_labels_operation_insert;
ALTER TABLE kaname.operations ENABLE ALWAYS TRIGGER user_access_labels_operation_interrupt;
ALTER TABLE kaname.operations ENABLE ALWAYS TRIGGER user_access_labels_operation_update;
ALTER TABLE kaname.operations ENABLE ALWAYS TRIGGER user_access_labels_operation_delete;
ALTER TABLE kaname.operations ENABLE ALWAYS TRIGGER user_access_labels_operation_truncate;

-- ModifiedAt, CreatedBy, description и type URL следуют UpdateUser/NewFromContext.
-- Проверку публичной Any до вызова выполняет типизированный порт. NULL legacy
-- account_id даёт личное владение и отсутствие ключа в account-scoped ленте.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_user_access_labels_operation_create_v1(
    p_id text,p_created_at timestamptz,p_user_id text,p_account_id text,p_metadata bytea,
    p_actor_type text,p_actor_id text,p_display_name text
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $create$
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF coalesce(p_id,'') COLLATE "C" !~ '^iop[0-9a-hjkmnp-tv-z]{17}$'
        OR p_created_at IS NULL OR NOT isfinite(p_created_at)
        OR coalesce(p_user_id,'') COLLATE "C" !~ '^usr[a-zA-Z0-9_-]{1,61}$'
        OR coalesce(octet_length(p_metadata),0)=0 OR p_display_name IS NULL
        OR coalesce(p_actor_type,'') NOT IN ('user','service_account')
        OR coalesce(octet_length(p_actor_id),0) NOT BETWEEN 1 AND 64
        OR p_actor_id='anonymous' OR p_actor_id ~ '[:#*[:space:][:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid protected user operation' USING ERRCODE='22023';
    END IF;
    INSERT INTO kaname.operations (id,description,created_at,created_by,modified_at,done,
        metadata_type,metadata_data,resource_id,account_id,principal_type,principal_id,
        principal_display_name,user_access_labels)
    SELECT p_id,'Update user '||u.id,p_created_at,p_actor_id,p_created_at,false,
        'type.googleapis.com/kaname.cloud.iam.v1.UpdateUserMetadata',p_metadata,u.id,u.account_id,
        p_actor_type,p_actor_id,p_display_name,true
    FROM ONLY kaname.users u
    WHERE u.id=p_user_id AND u.account_id IS NOT DISTINCT FROM nullif(p_account_id,'');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'protected user operation target or legacy account changed' USING ERRCODE='40001';
    END IF;
END;
$create$;
-- +goose StatementEnd

-- Удаляем также EXECUTE, выданный ALTER DEFAULT PRIVILEGES.
-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure; recipient record;
BEGIN
    FOREACH fn IN ARRAY ARRAY[
        'kaname._authority_user_access_labels_operation_guard_v1()'::regprocedure,
        'kaname._authority_user_access_labels_operation_create_v1(text,timestamptz,text,text,bytea,text,text,text)'::regprocedure
    ] LOOP
        FOR recipient IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
            WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
                CASE WHEN recipient.grantee=0 THEN 'PUBLIC' ELSE format('%I',recipient.rolname) END);
        END LOOP;
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
LOCK TABLE ONLY kaname.operations IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $pending$
BEGIN
    IF current_setting('transaction_isolation') NOT IN ('read committed','read uncommitted') THEN
        RAISE EXCEPTION 'rolling back operation protection requires a current snapshot' USING ERRCODE='25001';
    END IF;
    IF EXISTS(SELECT FROM ONLY kaname.operations WHERE user_access_labels AND NOT done) THEN
        RAISE EXCEPTION 'finish or cancel protected pending user operations before rollback' USING ERRCODE='55000';
    END IF;
END;
$pending$;
-- +goose StatementEnd
DROP FUNCTION kaname._authority_user_access_labels_operation_create_v1(text,timestamptz,text,text,bytea,text,text,text);
DROP TRIGGER user_access_labels_operation_truncate ON kaname.operations;
DROP TRIGGER user_access_labels_operation_delete ON kaname.operations;
DROP TRIGGER user_access_labels_operation_interrupt ON kaname.operations;
DROP TRIGGER user_access_labels_operation_update ON kaname.operations;
DROP TRIGGER user_access_labels_operation_insert ON kaname.operations;
DROP FUNCTION kaname._authority_user_access_labels_operation_guard_v1();
ALTER TABLE kaname.operations DROP COLUMN user_access_labels;
