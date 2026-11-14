-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Приёмка: docs/engineering/acceptance/grant-authority-matches-the-whole-effect.md
-- §8.3: OLD authority после всех mutation waits; kaname#1034.
-- GLOBAL cluster mutation: закрытый table profile защищает также compat raw
-- sources. Это не account-local оптимизация и не разрешение на DML.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_cluster_admin_preflight(p_type text,p_id text) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; at_time timestamptz;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF NOT coalesce(proof->>'kind'='cluster' AND proof->>'purpose'='participant' AND proof->>'mode'='global',false) THEN
  RAISE EXCEPTION 'cluster final decision entry required' USING ERRCODE='42501';
 END IF;
 IF p_type IS NULL OR p_type NOT IN ('user','service_account') OR p_id IS NULL OR p_id='' OR length(p_id)>64 THEN
  RAISE EXCEPTION 'invalid cluster decision target' USING ERRCODE='22023';
 END IF;
 -- Полный native/source readset, включая scope view, группы, альтернативные
 -- roleless/role carriers, checkpoint и named holders fold-delete. Табличные
 -- locks исключают также absent-row/typed-collision phantom до Commit.
 LOCK TABLE kaname.access_binding_emitted_tuples,kaname.access_binding_subjects,
  kaname.access_binding_target_members,kaname.access_bindings,kaname.accounts,
  kaname.catalog_module,kaname.catalog_resource,kaname.catalog_verb,kaname.clusters,
  kaname.grant_delegations,kaname.group_members,kaname.groups,kaname.memberships,
  kaname.producer_source_receipt,kaname.projects,kaname.public_read_publication,
  kaname.resource_mirror,kaname.resource_parent_edge,kaname.resource_registration_pointer,
  kaname.resource_registration_retirement,kaname.resource_registration_scope,
  kaname.role_bind_role_rule,kaname.role_create_binding_rule,kaname.role_rule_ref,
  kaname.role_rule_selectors,kaname.role_selector_verbs_pending,kaname.role_verb,
  kaname.roles,kaname.service_accounts,kaname.users IN SHARE MODE;
 LOCK TABLE kaname.cluster_admin_grants,kaname.relation_fact,
  kaname.authority_policy_epoch IN SHARE ROW EXCLUSIVE MODE;
 LOCK TABLE kaname.audit_outbox,kaname.fga_outbox IN ROW EXCLUSIVE MODE;
 -- View получает собственный relation lock до часов, не только locks базовых таблиц.
 LOCK TABLE kaname.resource_scope_edge IN ACCESS SHARE MODE;
 PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam:cluster-admin-revoke:cluster_root'));
 -- SELECT FOR UPDATE чужого читателя не конфликтует с SHARE table lock.
 -- Поэтому фактические изменяемые строки ждём отдельно до decision_at.
 PERFORM id FROM kaname.cluster_admin_grants WHERE subject_type=p_type AND subject_id=p_id ORDER BY id FOR UPDATE;
 PERFORM 1 FROM kaname.relation_fact WHERE object_type='cluster' AND object_id='cluster_root'
  AND relation='system_admin' AND subject=p_type||':'||p_id FOR UPDATE;
 PERFORM id FROM kaname.clusters WHERE id='cluster_root' FOR KEY SHARE;
 PERFORM key FROM kaname.authority_policy_epoch WHERE key IN ('*',p_type||':'||p_id) ORDER BY key COLLATE "C" FOR UPDATE;
 -- nextval захватывает sequence lock, а пропущенный ID не является grant.
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_catalog.pg_backend_pid()
  AND l.locktype='relation' AND l.relation='kaname.fga_outbox_id_seq'::regclass
  AND l.mode='RowExclusiveLock' AND l.granted) THEN
  PERFORM pg_catalog.nextval('kaname.fga_outbox_id_seq'::regclass);
 END IF;
 at_time:=pg_catalog.clock_timestamp();
 UPDATE pg_temp.kaname_authority_attestation SET decision_at=at_time;
 RETURN at_time;
END $$;
-- +goose StatementEnd
GRANT EXECUTE ON FUNCTION kaname.authority_cluster_admin_preflight(text,text) TO PUBLIC;
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd
DROP FUNCTION kaname.authority_cluster_admin_preflight(text,text);
