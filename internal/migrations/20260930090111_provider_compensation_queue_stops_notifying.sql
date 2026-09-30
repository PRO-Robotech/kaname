-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- provider_compensation_queue_stops_notifying — УВЕДОМЛЕНИЕ очереди компенсаций
-- саги у внешнего поставщика покидает схему: триггер
-- `provider_compensation_outbox_notify_trg` и его функция
-- `kaname.provider_compensation_outbox_notify()` (задача PRO-Robotech/kaname#363).
--
-- Санкция: предмет #363 — посадка личности у службы одна, административная
-- дорога к поставщику снята вместе с дренажом компенсаций и писателем намерения
-- (`internal/clients/provider_compensation_outbox.go`). Доводы там; здесь — то,
-- что нужно читателю СХЕМЫ.
--
-- =============================================================================
-- ПОЧЕМУ НОВАЯ МИГРАЦИЯ
-- =============================================================================
-- Триггер и функцию завёл свод (`0001_initial.sql`). Правка применённого файла
-- до базы, где он применён, не доезжает: мигратор сверяет версию, а не
-- содержимое (ban #5).
--
-- =============================================================================
-- ЧТО СНИМАЕТСЯ И ЧТО ОСТАЁТСЯ
-- =============================================================================
-- Канал `kaname_provider_compensation_outbox` будил дренаж компенсаций, и
-- слушателя у него больше нет: дренаж снят. Строк в очередь не кладёт ни один
-- путь, поэтому уведомление не будило бы никого, даже если бы слушатель был.
-- Триггер, шлющий в канал, который никто не слушает, со стороны неотличим от
-- работающего быстрого пути; расхождение держит гейт
-- `TestIntegration_EveryProducedNotifyChannelIsNamedByAConsumer`.
--
-- ОЧЕРЕДЬ ОСТАЁТСЯ. Строки, записанные прежней посадкой до её снятия, в ней
-- могли остаться: их держит видимыми перепись очереди
-- (`cmd/kaname/provider_compensation_wiring.go`), доставленные снимает уборщик.
-- Снятие самой таблицы — отдельный предмет, и строк оно не должно терять молча.
--
-- Строк миграция не читает и не пишет.
--
-- =============================================================================
-- ЗАХВАТ
-- =============================================================================
-- Снятие триггера берёт на очередь ИСКЛЮЧИТЕЛЬНЫЙ захват (измерено `pg_locks`
-- на Postgres 16.15: `AccessExclusiveLock`). Писателей у очереди нет; её
-- перепись и уборщик ждут конца наката, а он не трогает ни одной строки.

-- +goose Up

DROP TRIGGER IF EXISTS provider_compensation_outbox_notify_trg ON kaname.provider_compensation_outbox;
DROP FUNCTION IF EXISTS kaname.provider_compensation_outbox_notify();

-- +goose Down

-- Откат возвращает СТРОЕНИЕ ровно в том виде, в каком его оставил свод
-- `0001_initial.sql`: функцию под тем же именем и триггер на вставку. Совпадение
-- держит проба `TestIntegration_ProviderCompensationNotifyRollsBackAndReapplies`.

-- +goose StatementBegin
CREATE FUNCTION kaname.provider_compensation_outbox_notify() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM pg_notify('kaname_provider_compensation_outbox', NEW.id::text);
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER provider_compensation_outbox_notify_trg AFTER INSERT ON kaname.provider_compensation_outbox FOR EACH ROW EXECUTE FUNCTION kaname.provider_compensation_outbox_notify();
