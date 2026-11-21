-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Приёмка: docs/engineering/acceptance/grant-authority-matches-the-whole-effect.md §8.3.
-- kaname#1034: неожиданный конфликт deferred metadata отменяет всю попытку;
-- apply разных accounts сохраняет совместимый shared carrier latch.
-- CREATE OR REPLACE сохраняет владельца и закрытый ACL опубликованной функции.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_policy_carrier_flush() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE roles text[]; r text;
BEGIN
 -- Первый callback видит весь metadata set TX, независимо от порядка OLD/NEW
 -- business rows. Следующие callbacks видят пустой set. Inventory не читается.
 SELECT array_agg(role_id ORDER BY role_id COLLATE "C") INTO roles FROM (
  SELECT role_id FROM kaname.authority_policy_carrier_pending
  WHERE transaction_id=pg_current_xact_id() AND backend_pid=pg_backend_pid()
  ORDER BY role_id COLLATE "C" LIMIT 4097) pending;
 IF cardinality(roles)>4096 THEN RAISE EXCEPTION 'carrier revision budget exceeded' USING ERRCODE='54000'; END IF;
 -- Фаза 1: весь собственный набор блокируется до первого revision UPDATE.
 -- NOWAIT не заменяет relation preflight до final clock. При конфликте
 -- вызывающий откатывает всю попытку и заново проверяет OLD authority.
 BEGIN
  FOREACH r IN ARRAY coalesce(roles,ARRAY[]::text[]) LOOP
   PERFORM key FROM kaname.authority_policy_epoch WHERE key='carriers:role:'||r FOR UPDATE NOWAIT;
   IF NOT FOUND THEN RAISE EXCEPTION 'carrier revision missing' USING ERRCODE='40001'; END IF;
  END LOOP;
 EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'carrier revision is busy' USING ERRCODE='40001';
 END;
 -- Фаза 2: все строки уже удерживаются до конца TX; ожидания чужой
 -- revision здесь нет. Частичный flush и пропуск занятой роли запрещены.
 FOREACH r IN ARRAY coalesce(roles,ARRAY[]::text[]) LOOP
  UPDATE kaname.authority_policy_epoch SET revision=revision+1 WHERE key='carriers:role:'||r;
  IF NOT FOUND THEN RAISE EXCEPTION 'carrier revision missing' USING ERRCODE='40001'; END IF;
 END LOOP;
 DELETE FROM kaname.authority_policy_carrier_pending WHERE transaction_id=pg_current_xact_id() AND backend_pid=pg_backend_pid();
 RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION kaname.authority_policy_carrier_flush() FROM PUBLIC;
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd
-- Восстанавливается исходное тело; старые writers нельзя оставлять активными.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_policy_carrier_flush() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE roles text[]; r text;
BEGIN
 -- Первый callback видит весь metadata set TX, независимо от порядка OLD/NEW
 -- business rows. Следующие callbacks видят пустой set. Inventory не читается.
 SELECT array_agg(role_id ORDER BY role_id COLLATE "C") INTO roles FROM (
  SELECT role_id FROM kaname.authority_policy_carrier_pending
  WHERE transaction_id=pg_current_xact_id() AND backend_pid=pg_backend_pid()
  ORDER BY role_id COLLATE "C" LIMIT 4097) pending;
 IF cardinality(roles)>4096 THEN RAISE EXCEPTION 'carrier revision budget exceeded' USING ERRCODE='54000'; END IF;
 FOREACH r IN ARRAY coalesce(roles,ARRAY[]::text[]) LOOP
  UPDATE kaname.authority_policy_epoch SET revision=revision+1 WHERE key='carriers:role:'||r;
  IF NOT FOUND THEN RAISE EXCEPTION 'carrier revision missing' USING ERRCODE='40001'; END IF;
 END LOOP;
 DELETE FROM kaname.authority_policy_carrier_pending WHERE transaction_id=pg_current_xact_id() AND backend_pid=pg_backend_pid();
 RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION kaname.authority_policy_carrier_flush() FROM PUBLIC;
