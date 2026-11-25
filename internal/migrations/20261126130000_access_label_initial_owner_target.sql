-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();

-- Квитанция переживает штатный отзыв и удаление привязки. Удаление
-- обычных записей IAM не должно снова открыть право на первую выдачу.
CREATE TABLE kaname.authority_initial_access_label_apply_issuance (
    definition_id uuid PRIMARY KEY,
    definition_revision bigint NOT NULL CHECK (definition_revision>0),
    account_id text NOT NULL CHECK (account_id<>''),
    project_id text NOT NULL,
    recipient_user_id text NOT NULL CHECK (recipient_user_id<>''),
    role_id text NOT NULL UNIQUE CHECK (role_id<>''),
    binding_id text NOT NULL UNIQUE CHECK (binding_id<>''),
    issued_at timestamptz NOT NULL CHECK (isfinite(issued_at))
);

-- Единственный адресат определяется после глобального входа установщика.
-- Проект и редакция определения проверяются в той же транзакции выдачи.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_initial_access_label_apply_target_v1(
    p_account text, p_project text, p_definition uuid, p_revision bigint
) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
    recipient text;
    proof jsonb;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    proof := kaname.authority_protocol_attestation();
    IF proof->>'mode' IS DISTINCT FROM 'global'
       OR proof->>'kind' IS DISTINCT FROM 'role'
       OR proof->>'purpose' IS DISTINCT FROM 'participant'
       OR proof->>'writer_contract' IS DISTINCT FROM '2'
       OR proof->>'consumer_abi' IS DISTINCT FROM '2'
       OR proof->>'consumer_profile' IS DISTINCT FROM 'typed'
       OR proof->>'consumer_finalized' IS DISTINCT FROM 'false' THEN
        RAISE EXCEPTION 'initial access label apply requires signed full installation entry' USING ERRCODE='42501';
    END IF;
    IF coalesce(p_account,'')='' OR p_project IS NULL
       OR p_definition IS NULL OR p_definition='00000000-0000-0000-0000-000000000000'::uuid
       OR coalesce(p_revision,0)<1 THEN
        RAISE EXCEPTION 'initial access label apply requires an exact definition revision and scope'
            USING ERRCODE='22023';
    END IF;

    -- Тот же порядок, что у владельца объявления. Изменение значений
    -- обновляет revision определения, поэтому оно ждёт этот lock.
    LOCK TABLE kaname.authority_access_label_definition IN SHARE ROW EXCLUSIVE MODE;
    SELECT u.id INTO recipient
    FROM ONLY kaname.accounts a
    JOIN ONLY kaname.users u ON u.id=a.owner_user_id
    JOIN ONLY kaname.memberships m ON m.user_id=u.id AND m.account_id=a.id AND m.state='ACTIVE'
    JOIN kaname.authority_access_label_definition d ON d.id=p_definition AND d.revision=p_revision
    JOIN kaname.catalog_resource r ON (r.module,r.resource)=(d.module,d.resource) AND r.live
    JOIN kaname.catalog_module mod ON mod.module=r.module AND mod.live
    WHERE a.id=p_account AND u.invite_status='ACTIVE' AND u.email_verified_at IS NOT NULL
      AND ((p_project='' AND d.scope_kind='account' AND d.scope_id=a.id)
        OR (p_project<>'' AND d.scope_kind='project' AND d.scope_id=p_project
            AND EXISTS (SELECT 1 FROM ONLY kaname.projects p
                        WHERE p.id=p_project AND p.account_id=a.id FOR SHARE OF p)))
      AND EXISTS (SELECT 1 FROM kaname.authority_access_label_value v WHERE v.definition_id=d.id)
    FOR UPDATE OF d FOR SHARE OF a,u,m,r,mod;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'initial access label apply target does not match live owner, scope and definition'
            USING ERRCODE='42501';
    END IF;
    RETURN recipient;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private_initial_apply_target$
DECLARE
    signature constant text := 'kaname._authority_initial_access_label_apply_target_v1(text,text,uuid,bigint)';
    relation constant text := 'kaname.authority_initial_access_label_apply_issuance';
    grantee record;
BEGIN
    FOR grantee IN
        SELECT DISTINCT a.grantee,r.rolname
        FROM pg_catalog.pg_class c
        CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
        WHERE c.oid=to_regclass(relation) AND a.grantee<>c.relowner
    LOOP
        EXECUTE format('REVOKE ALL ON TABLE %s FROM %s',relation,
            CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
    END LOOP;
    FOR grantee IN
        SELECT DISTINCT a.grantee,r.rolname
        FROM pg_catalog.pg_proc p
        CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
        WHERE p.oid=to_regprocedure(signature) AND a.grantee<>p.proowner
    LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',signature,
            CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
    END LOOP;
END;
$private_initial_apply_target$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM kaname.authority_initial_access_label_apply_issuance) THEN
        RAISE EXCEPTION 'initial access label issuance history must be preserved' USING ERRCODE='55000';
    END IF;
END $$;
-- +goose StatementEnd
DROP FUNCTION kaname._authority_initial_access_label_apply_target_v1(text,text,uuid,bigint);
DROP TABLE kaname.authority_initial_access_label_apply_issuance;
