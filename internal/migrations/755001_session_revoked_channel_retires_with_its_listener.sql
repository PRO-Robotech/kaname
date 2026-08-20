-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 755001_session_revoked_channel_retires_with_its_listener — канал уведомления
-- снимается вместе со своим триггером, потому что потребителя у него нет и
-- построить его нельзя.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ
--
-- Триггер на `kacho_iam.session_revocations` объявлен быстрым путём отзыва:
-- вставка строки шлёт `pg_notify('session_revoked', NEW.token_jti)`. Производитель
-- работает. Слушателей — НОЛЬ, и ноль их с первого дня схемы: предикат
-- `git grep -n 'session_revoked' -- '*.go'` на 04e2e523f даёт четыре попадания, и
-- все четыре — комментарии в сгенерированном по контракту коде.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ СНИМАЕТСЯ, А НЕ ДОСТРАИВАЕТСЯ
--
-- Слушателем по замыслу был край. Край слушать не может — и не «пока не
-- научили», а по построению: драйвера Postgres у него нет вовсе
-- (`git grep -ln 'jackc/pgx' -- 'gateway/**/*.go'` → ноль файлов). Выдать краю
-- соединение с базой iam значило бы прочитать чужую базу напрямую — это ban #8
-- (database-per-service), то есть быстрый путь В ЭТОЙ ФОРМЕ неисполним, а не
-- недоделан.
--
-- Путь того же назначения в продукте УЖЕ ЕСТЬ и сделан правильной формой: iam
-- дренит собственную очередь `subject_change_outbox` и зовёт край по gRPC
-- (`InternalAuthzCacheService.InvalidateSubject`). Уведомление о самой очереди
-- ходит своим каналом (`kacho_iam_subject_outbox_added`), у которого слушатель
-- есть. Держать рядом второй канал того же назначения без потребителя — два
-- места об одном предмете, из которых работает одно.
--
-- Что при этом НЕ снимается и почему: таблица `session_revocations` остаётся —
-- у неё живые писатель (logout с края) и читатели (`IsRevoked`, `ListByUser`,
-- `DeleteExpired`). Снимается ровно объявление уведомления.
--
-- Проверка отзыва предъявленного токена на крае этой миграцией не затрагивается:
-- она идёт интроспекцией у провайдера на каждом запросе и от этого канала не
-- зависела никогда.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОРЯДОК
--
-- Снимается только ОБЪЯВЛЕНИЕ (триггер и его функция). Данных у канала нет:
-- уведомление не хранится, обратного заполнения не требуется, строки таблицы не
-- трогаются — обратимость поэтому тривиальна, и Down восстанавливает
-- ровно снятое.
--
-- Регрессия: services/iam/internal/migrations/notify_channel_has_a_listener_integration_test.go
-- — утверждает по ЖИВОЙ схеме после проигрывания, что производителя больше нет,
-- и парно, что канал очереди со слушателем производителя сохранил.

-- +goose Up

DROP TRIGGER IF EXISTS session_revocations_notify_trg ON kacho_iam.session_revocations;
DROP FUNCTION IF EXISTS kacho_iam.session_revocations_notify();

-- +goose Down

-- +goose StatementBegin
CREATE FUNCTION kacho_iam.session_revocations_notify() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM pg_notify('session_revoked', NEW.token_jti);
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER session_revocations_notify_trg
    AFTER INSERT ON kacho_iam.session_revocations
    FOR EACH ROW EXECUTE FUNCTION kacho_iam.session_revocations_notify();
