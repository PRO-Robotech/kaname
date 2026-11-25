-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- Частный шаг будущего writer. На входе только публичные идентификаторы.
-- Резерв аудита должен быть передан insertAuditEventWithIDTx. Отдельно
-- остаются уникальные ключи самого удостоверения, источники надзора и
-- публикация. Эта функция не выдаёт часы и не создаёт attestation.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_user_token_issue_storage_wait_v1(
    p_actor_type text, p_actor_id text, p_owner text, p_audit text
) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
    human_ids text[];
    locked_humans integer;
    quota_key text;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed'
       OR p_actor_type IS NULL OR p_actor_type NOT IN ('user','service_account')
       OR p_actor_id IS NULL OR octet_length(p_actor_id) NOT BETWEEN 1 AND 64
       OR p_owner IS NULL OR octet_length(p_owner) NOT BETWEEN 1 AND 64
       OR p_audit IS NULL OR octet_length(p_audit) NOT BETWEEN 24 AND 34
       OR p_audit !~ '^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$' THEN
        RAISE EXCEPTION 'invalid user token storage wait' USING ERRCODE='22023';
    END IF;

    human_ids:=ARRAY[p_owner];
    IF p_actor_type='service_account' THEN
        PERFORM 1 FROM kaname.service_accounts WHERE id=p_actor_id FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'user token issuer changed' USING ERRCODE='P1036';
        END IF;
    ELSIF p_actor_id<>p_owner THEN
        human_ids:=array_append(human_ids,p_actor_id);
    END IF;
    PERFORM 1 FROM kaname.users WHERE id=ANY(human_ids) ORDER BY id COLLATE "C" FOR SHARE;
    GET DIAGNOSTICS locked_humans=ROW_COUNT;
    IF locked_humans<>cardinality(human_ids) THEN
        RAISE EXCEPTION 'user token participants changed' USING ERRCODE='P1036';
    END IF;

    LOCK TABLE ONLY kaname.user_oauth_clients IN ROW EXCLUSIVE MODE;
    -- quota_count сначала читает потолок, затем INSERT ... ON CONFLICT/UPDATE
    -- одной строки. Отсутствующий потолок не подтверждает готовность к записи.
    PERFORM 1 FROM kaname.own_ceilings WHERE kind='iam.user.credential' FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'user credential ceiling changed' USING ERRCODE='P1036';
    END IF;
    LOCK TABLE ONLY kaname.project_resource_quotas IN ROW EXCLUSIVE MODE;
    quota_key:=kaname._authority_crud_unique_key_v3('project_resource_quotas',
        jsonb_build_object('carrier_type','iam.user','carrier_id',p_owner,'kind','iam.user.credential'));
    -- Тот же ключ, который берёт BEFORE INSERT authority_crud_unique_guard_v3.
    -- Он защищает отсутствие счётчика; существующую строку удерживаем и от
    -- DELETE/UPDATE без изменения её ключа.
    PERFORM pg_advisory_xact_lock(1262569303,hashtext(quota_key));
    PERFORM 1 FROM kaname.project_resource_quotas
        WHERE carrier_type='iam.user' AND carrier_id=p_owner AND kind='iam.user.credential' FOR UPDATE;

    -- Порядок соответствует INSERT: сначала relation, затем ключ BEFORE INSERT.
    LOCK TABLE ONLY kaname.audit_outbox IN ROW EXCLUSIVE MODE;
    PERFORM pg_advisory_xact_lock(1262569298,hashtext(p_audit));
    PERFORM 1 FROM kaname.audit_outbox WHERE id=p_audit FOR UPDATE;
    IF FOUND THEN
        RAISE EXCEPTION 'user token audit ID already exists' USING ERRCODE='23505';
    END IF;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION kaname._authority_user_token_issue_storage_wait_v1(text,text,text,text) FROM PUBLIC;

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_user_token_issue_storage_wait_v1(text,text,text,text);
