-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- LISTEN/NOTIFY-триггер на очереди reconcile-событий (resource_reconcile_outbox):
-- переводит дренаж очереди с poll-only на NOTIFY-driven, в паритет с fga_outbox.
--
-- Каждый INSERT события (эмит из RegisterResource/UnregisterResource в writer-tx,
-- атомарно с изменением resource_mirror) шлет pg_notify на канал
-- kacho_iam_resource_reconcile_outbox с payload = id строки. Reconciler-worker
-- слушает канал и просыпается по уведомлению, дренажа очередь в пределах одного
-- reconcile-прохода — поэтому материализация label-selector гранта появляется в
-- идеальной полосе, а не ждет следующего poll-тика. Poll остается лишь fallback на
-- случай пропущенного NOTIFY (idle-conn-reset); периодический полный sweep
-- (defense-in-depth) не затрагивается.
--
-- Byte-mirror функции kacho_iam.fga_outbox_notify: AFTER INSERT FOR EACH ROW,
-- RETURN NEW. pg_notify доставляется слушателю в момент COMMIT writer-tx, поэтому
-- уведомление консистентно с видимостью вставленной строки.

-- +goose StatementBegin
CREATE FUNCTION kacho_iam.resource_reconcile_outbox_notify() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM pg_notify('kacho_iam_resource_reconcile_outbox', NEW.id::text);
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER resource_reconcile_outbox_notify_trigger
    AFTER INSERT ON kacho_iam.resource_reconcile_outbox
    FOR EACH ROW EXECUTE FUNCTION kacho_iam.resource_reconcile_outbox_notify();

-- +goose Down

DROP TRIGGER IF EXISTS resource_reconcile_outbox_notify_trigger ON kacho_iam.resource_reconcile_outbox;
DROP FUNCTION IF EXISTS kacho_iam.resource_reconcile_outbox_notify();
