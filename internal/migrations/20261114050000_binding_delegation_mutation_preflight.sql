-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Приёмка: docs/engineering/acceptance/role-rights-stay-within-what-is-named.md
-- ESC-32, Р4; APPROVED 3131d7ddfffa9b66857b94c70138b6ebfe7bdb77c7ca07f5333db88aefaae690.
-- kaname#1034: блокировки таблиц фактической мутации Binding/GD до финальных часов.
-- Не выдаёт полномочия DML и не заменяет защиту источников и областей строк.
-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_grant_mutation_preflight(p_profile text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; sequence_id regclass;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR coalesce(proof->>'mode','') NOT IN ('accounts','global') THEN
  RAISE EXCEPTION 'grant mutation requires signed coordinator entry' USING ERRCODE='42501';
 END IF;
 IF NOT coalesce(
   (p_profile='binding' AND proof->>'kind'='binding' AND proof->>'purpose' IN ('decision','participant'))
   OR (p_profile='withdrawal' AND proof->>'kind' IN ('binding','delegation') AND proof->>'purpose'='participant')
   OR (p_profile='delegation' AND proof->>'kind'='delegation' AND proof->>'purpose'='participant'),false) THEN
  RAISE EXCEPTION 'grant mutation profile does not match signed entry' USING ERRCODE='42501';
 END IF;
 IF p_profile='delegation' THEN
  LOCK TABLE kaname.audit_outbox,kaname.authority_binding_epoch,
   kaname.authority_policy_epoch,kaname.grant_delegations IN ROW EXCLUSIVE MODE;
 ELSE
  -- Закрытое объединение: родитель/состав, синхронная свёртка, журналы
  -- событий, эпохи policy/binding и отложенные метаданные носителей. Отзыв GD
  -- добавляет настоящего родителя, не подменяет подписанный kind на Binding.
  LOCK TABLE kaname.access_binding_emitted_tuples,kaname.access_binding_subjects,
   kaname.access_binding_target_members,kaname.access_bindings,kaname.audit_outbox,
   kaname.authority_binding_epoch,kaname.authority_policy_carrier_pending,
   kaname.authority_policy_epoch,kaname.fga_outbox,kaname.relation_fact,
   kaname.resource_journal,kaname.resource_reconcile_outbox,
   kaname.subject_change_outbox IN ROW EXCLUSIVE MODE;
  IF proof->>'kind'='delegation' THEN
   LOCK TABLE kaname.grant_delegations IN ROW EXCLUSIVE MODE;
  END IF;
  -- nextval держит RowExclusiveLock последовательности до конца TX (PG16).
  -- Допустимы пропуски ID, как при откате; бизнес-строки до проверки не меняются.
  FOREACH sequence_id IN ARRAY ARRAY[
   'kaname.fga_outbox_id_seq'::regclass,
   'kaname.resource_journal_sequence_no_seq'::regclass,
   'kaname.resource_reconcile_outbox_id_seq'::regclass,
   'kaname.subject_change_outbox_id_seq'::regclass
  ] LOOP
   IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_catalog.pg_backend_pid()
    AND l.locktype='relation' AND l.relation=sequence_id
    AND l.mode='RowExclusiveLock' AND l.granted) THEN
    PERFORM pg_catalog.nextval(sequence_id);
   END IF;
  END LOOP;
 END IF;
END $$;
-- +goose StatementEnd
GRANT EXECUTE ON FUNCTION kaname.authority_grant_mutation_preflight(text) TO PUBLIC;
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd
DROP FUNCTION kaname.authority_grant_mutation_preflight(text);
