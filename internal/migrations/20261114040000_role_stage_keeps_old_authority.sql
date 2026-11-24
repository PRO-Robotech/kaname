-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Приёмка: docs/engineering/acceptance/grant-authority-matches-the-whole-effect.md §8.3.
-- kaname#1034: role decision получает тот же защищённый epoch lock, что
-- participant spool. Purpose не подменяется: attestation проверяет actual
-- transaction, invoker, active bundle и coordinator scopes до выдачи proof.
-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_role_stage_epoch_lock(p_accounts text[],p_expected jsonb) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; actual jsonb; at_time timestamptz; sequence_id regclass;
BEGIN
 IF p_expected IS NULL OR pg_catalog.jsonb_typeof(p_expected)<>'object' THEN RAISE EXCEPTION 'binding epoch snapshot is absent' USING ERRCODE='40001'; END IF;
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL THEN RAISE EXCEPTION 'role stage requires signed entry' USING ERRCODE='42501'; END IF;
 IF proof->>'purpose' IS DISTINCT FROM 'decision' OR proof->>'kind' IS DISTINCT FROM 'role' THEN RAISE EXCEPTION 'role stage requires role decision' USING ERRCODE='42501'; END IF;
 IF proof->>'mode' IS DISTINCT FROM 'accounts' AND proof->>'mode' IS DISTINCT FROM 'global' THEN RAISE EXCEPTION 'invalid role stage coordinator mode' USING ERRCODE='42501'; END IF;
 IF p_accounts IS NULL THEN
  IF proof->>'mode' IS DISTINCT FROM 'global' THEN RAISE EXCEPTION 'binding global epoch requires global entry' USING ERRCODE='42501'; END IF;
 ELSE
  IF pg_catalog.cardinality(p_accounts)=0 OR EXISTS(SELECT 1 FROM pg_catalog.unnest(p_accounts) a WHERE a IS NULL OR a='') THEN RAISE EXCEPTION 'invalid binding epoch scope'; END IF;
  IF proof->>'mode'='accounts' AND (pg_catalog.jsonb_typeof(proof->'accounts') IS DISTINCT FROM 'array' OR NOT (proof->'accounts') @> pg_catalog.to_jsonb(p_accounts)) THEN RAISE EXCEPTION 'epoch accounts exceed role decision scope' USING ERRCODE='42501'; END IF;
 END IF;
 -- SELECT FOR UPDATE держит только ROW SHARE на таблице. SHARE blocker
 -- пережил бы row prelock и задержал DML уже после решения. Закрытый union
 -- actual Create/Update footprints берётся в одном порядке ДО final clock.
 -- Включены триггеры resource journal, policy/binding epochs и deferred
 -- carrier flush, а также ledger/outbox/fold; DML authority этим не выдаётся.
 LOCK TABLE kaname.access_binding_emitted_tuples,
   kaname.access_bindings,
   kaname.audit_outbox,
   kaname.authority_binding_epoch,
   kaname.authority_policy_carrier_pending,
   kaname.authority_policy_epoch,
   kaname.fga_outbox,
   kaname.relation_fact,
   kaname.resource_journal,
   kaname.resource_reconcile_outbox,
   kaname.role_bind_role_rule,
   kaname.role_create_binding_rule,
   kaname.role_rule_ref,
   kaname.role_rule_selectors,
   kaname.role_selector_verbs_pending,
   kaname.role_verb,
   kaname.roles IN ROW EXCLUSIVE MODE;
 -- У таблицы и её serial/identity sequence разные relation locks. nextval
 -- получает RowExclusiveLock sequence до конца TX и переносит ожидание
 -- ALTER SEQUENCE до final clock. Только закрытый actual union; никакого
 -- caller SQL, business DML или выдачи runtime прямых metadata privileges.
 -- Один номер на sequence на попытку допустимо пропускается (как rollback).
 -- Повторный epoch recheck не расходует номер: удерживаемый lock уже достаточен.
 FOREACH sequence_id IN ARRAY ARRAY[
   'kaname.fga_outbox_id_seq'::regclass,
   'kaname.resource_journal_sequence_no_seq'::regclass,
   'kaname.resource_reconcile_outbox_id_seq'::regclass
 ] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l
    WHERE l.pid=pg_catalog.pg_backend_pid() AND l.locktype='relation'
      AND l.relation=sequence_id AND l.mode='RowExclusiveLock' AND l.granted) THEN
   PERFORM pg_catalog.nextval(sequence_id);
  END IF;
 END LOOP;
 IF p_accounts IS NULL THEN
  PERFORM scope FROM kaname.authority_binding_epoch WHERE scope='' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'binding epochs are uninitialized' USING ERRCODE='40001'; END IF;
 ELSE
  PERFORM scope FROM kaname.authority_binding_epoch WHERE scope='' FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'binding epochs are uninitialized' USING ERRCODE='40001'; END IF;
  PERFORM scope FROM kaname.authority_binding_epoch WHERE scope=ANY(p_accounts) ORDER BY scope FOR SHARE;
  IF (SELECT count(*) FROM kaname.authority_binding_epoch WHERE scope=ANY(p_accounts))<>(SELECT count(DISTINCT a) FROM pg_catalog.unnest(p_accounts) a) THEN RAISE EXCEPTION 'binding epoch disappeared' USING ERRCODE='40001'; END IF;
 END IF;
 actual:=kaname.authority_binding_epoch_read(p_accounts);
 IF actual IS DISTINCT FROM p_expected THEN RAISE EXCEPTION 'binding stage changed' USING ERRCODE='40001'; END IF;
 at_time:=pg_catalog.clock_timestamp();
 UPDATE pg_temp.kaname_authority_attestation SET decision_at=at_time;
 RETURN at_time;
END $$;
-- +goose StatementEnd
GRANT EXECUTE ON FUNCTION kaname.authority_role_stage_epoch_lock(text[],jsonb) TO PUBLIC;
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd
DROP FUNCTION kaname.authority_role_stage_epoch_lock(text[],jsonb);
