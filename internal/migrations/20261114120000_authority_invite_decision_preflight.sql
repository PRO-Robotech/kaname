-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Приёмка: docs/engineering/acceptance/grant-authority-matches-the-whole-effect.md §8.3.
-- kaname#1034: invite OLD decision после полного ожидания. GLOBAL serialization
-- сохраняется явно; это не performance/cutover acceptance и не новый DML grant.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_invite_phase_snapshot()
RETURNS TABLE(phase text,enforcement text,protocol_version integer,model_id text,catalog_id text,projector_version text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT a.phase,p.enforcement,a.protocol_version,a.model_id,a.catalog_id,a.projector_version
 FROM kaname.authority_semantic_identity a JOIN kaname.authority_writer_protocol p USING(singleton)
 JOIN kaname.authority_bundle_handoff b USING(singleton)
 WHERE a.singleton AND a.protocol_version=1 AND p.protocol_version=a.protocol_version
 AND ((a.phase='prepared' AND p.enforcement='compatibility') OR (a.phase='active' AND p.enforcement='strict'))
 AND (a.model_id,a.catalog_id,a.projector_version)=(b.model_id,b.catalog_id,b.projector_version)
$$;
-- +goose StatementEnd
-- RR accessor выше сообщает только metadata: не attestation и не activation.
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_invite_phase_held()
RETURNS TABLE(phase text,enforcement text,protocol_version integer,model_id text,catalog_id text,projector_version text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF NOT coalesce(proof->>'kind'='identity' AND proof->>'purpose'='participant' AND proof->>'mode'='global',false) THEN
  RAISE EXCEPTION 'invite identity participant required' USING ERRCODE='42501';
 END IF;
 RETURN QUERY SELECT s.* FROM kaname.authority_invite_phase_snapshot() s
 WHERE s.model_id=proof->>'model_id' AND s.catalog_id=proof->>'catalog_id'
 AND s.projector_version=proof->>'projector_version' AND s.protocol_version=(proof->>'protocol')::integer;
 IF NOT FOUND THEN RAISE EXCEPTION 'invite bundle phase changed' USING ERRCODE='P1036'; END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_invite_preflight(p_binding boolean) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE sequence_name text; sequence_oid regclass;
BEGIN
 PERFORM * FROM kaname.authority_invite_phase_held();
 IF p_binding IS NULL THEN RAISE EXCEPTION 'invalid invite mutation shape' USING ERRCODE='22023'; END IF;
 -- Один лексический порядок и максимальный режим сразу. EXCLUSIVE ждёт в том
 -- числе plain SELECT FOR UPDATE/KEY SHARE; отдельная копия population не нужна.
 -- AB таблицы нужны также editor/source census без optional grant. Journal,
 -- fold, membership/identity epochs и mail-window безусловны для нового user.
 LOCK TABLE kaname.access_binding_emitted_tuples,
  kaname.access_binding_subjects,
  kaname.access_binding_target_members,
  kaname.access_bindings,
  kaname.accounts,
  kaname.audit_outbox,
  kaname.authority_binding_epoch,
  kaname.authority_policy_carrier_pending,
  kaname.authority_policy_epoch,
  kaname.catalog_module,
  kaname.catalog_resource,
  kaname.catalog_verb,
  kaname.cluster_admin_grants,
  kaname.clusters,
  kaname.fga_outbox,
  kaname.grant_delegations,
  kaname.group_members,
  kaname.groups,
  kaname.invite_mail_outbox,
  kaname.invite_mail_windows,
  kaname.issued_user_ids,
  kaname.memberships,
  kaname.object_project_binding,
  kaname.own_ceilings,
  kaname.producer_source_receipt,
  kaname.project_resource_quotas,
  kaname.projects,
  kaname.public_read_publication,
  kaname.registration_account_writer_switch,
  kaname.registration_legacy_cluster_writer_identity,
  kaname.relation_fact,
  kaname.resource_journal,
  kaname.resource_mirror,
  kaname.resource_parent_edge,
  kaname.resource_reconcile_outbox,
  kaname.resource_registration_pointer,
  kaname.resource_registration_retirement,
  kaname.resource_registration_scope,
  kaname.role_bind_role_rule,
  kaname.role_create_binding_rule,
  kaname.role_rule_ref,
  kaname.role_rule_selectors,
  kaname.role_selector_verbs_pending,
  kaname.role_verb,
  kaname.roles,
  kaname.service_accounts,
  kaname.subject_change_outbox,
  kaname.user_login_methods,
  kaname.users IN EXCLUSIVE MODE;
 -- Собственный lock view должен предшествовать final clock, как и её base tables.
 LOCK TABLE kaname.resource_scope_edge IN ACCESS SHARE MODE;
 -- Все фактические nextval в base/optional body. Пропуски значений разрешены,
 -- бизнес-данных preflight не пишет. Уже удерживаемый sequence lock повторно
 -- не потребляет значение. Проверяется именно granted lock текущего backend.
 FOREACH sequence_name IN ARRAY ARRAY['fga_outbox_id_seq','invite_mail_outbox_id_seq','resource_journal_sequence_no_seq','resource_reconcile_outbox_id_seq','subject_change_outbox_id_seq'] LOOP
  sequence_oid:=pg_catalog.to_regclass('kaname.'||sequence_name);
  IF sequence_oid IS NULL THEN RAISE EXCEPTION 'invite sequence missing: %',sequence_name USING ERRCODE='55000'; END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_catalog.pg_backend_pid()
   AND l.locktype='relation' AND l.relation=sequence_oid
   AND l.mode='RowExclusiveLock' AND l.granted) THEN
   PERFORM pg_catalog.nextval(sequence_oid);
  END IF;
 END LOOP;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_invite_final_clock() RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE at_time timestamptz;
BEGIN
 PERFORM * FROM kaname.authority_invite_phase_held();
 at_time:=pg_catalog.clock_timestamp();
 UPDATE pg_temp.kaname_authority_attestation SET decision_at=at_time;
 RETURN at_time;
END $$;
-- +goose StatementEnd
GRANT EXECUTE ON FUNCTION kaname.authority_invite_phase_snapshot() TO PUBLIC;
GRANT EXECUTE ON FUNCTION kaname.authority_invite_phase_held() TO PUBLIC;
GRANT EXECUTE ON FUNCTION kaname.authority_invite_preflight(boolean) TO PUBLIC;
GRANT EXECUTE ON FUNCTION kaname.authority_invite_final_clock() TO PUBLIC;
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd
DROP FUNCTION kaname.authority_invite_final_clock();
DROP FUNCTION kaname.authority_invite_preflight(boolean);
DROP FUNCTION kaname.authority_invite_phase_held();
DROP FUNCTION kaname.authority_invite_phase_snapshot();
