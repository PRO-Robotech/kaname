-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 20260829181500 — журнал смены субъекта теряет колонки доставки: доставлять
-- нечего и некому (kacho#1396).
--
-- ───────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ
--
-- `sent_at`, `attempt_count`, `last_error`, `notified_at` — величины ДОСТАВКИ:
-- их объявляет тот, кто обещает доставлять. Доставки у журнала не осталось —
-- толчок к краю снят (#1024), направление развёрнуто, соединение открывает
-- потребитель и читает журнал КУРСОРОМ. Ни писателя, ни читателя:
--
--   вставка         `repo/kacho/pg/access_binding_repo.go` пишет
--                   (subject_id, op, event_type, payload) — и только;
--   дренаж          снят вместе с адресатом (`cmd/kacho-iam/serve.go`):
--                   `UPDATE … SET sent_at` не исполняет никто;
--   сканер          снят там же (`outbox_metrics_wiring.go`) — «возраст самой
--                   старой неотправленной» на журнале без доставки описывал бы
--                   не сбой, а устройство, и рос бы на исправной службе;
--   проекция чтения `repo/kacho/pg/subject_change_repo.go` выбирает
--                   id, subject_id, op и тип субъекта из тела;
--   контракт        `InternalIAMService.PollSubjectChanges` этих величин не
--                   выставляет;
--   триггер         `subject_change_outbox_notify` читает только `NEW.id`.
--
-- Строка ложится со значением по умолчанию и остаётся в нём навсегда. Колонка,
-- которую никто не читает и не пишет, обещает механизм, которого нет.
--
-- ───────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ЭТО ОТДЕЛЬНАЯ МИГРАЦИЯ, А НЕ ЧАСТЬ #1024
--
-- Сужающий шаг расширения-сужения. Выкатка идёт репликами: между посадкой
-- нового кода и уходом старого есть окно, в котором прежний дренаж ещё жив и
-- исполняет `UPDATE … SET sent_at` по схеме, где колонки уже нет. Колонку
-- роняют ПОСЛЕ того, как писателей не осталось, — это средний шаг, а не
-- отсрочка. Условие начала (писателей в стволе ноль) проверяется предикатом
-- `git grep -c 'Table:[[:space:]]*subjectChangeOutboxTable' -- services/iam/cmd/kacho-iam/`.
--
-- ───────────────────────────────────────────────────────────────────────────
-- ИНДЕКС СНИМАЕТСЯ ЯВНО, А НЕ ЗАОДНО
--
-- `subject_change_pending_v2_idx` — частичный по `sent_at IS NULL`. Postgres
-- снял бы его сам вместе с колонкой, МОЛЧА: у `DROP COLUMN` это штатное
-- поведение, а не оплошность. Оператор стоит в тексте затем, чтобы снятие
-- индекса читалось из миграции, а не восстанавливалось по памяти о поведении
-- СУБД; исход обеих форм один и тот же и утверждён пробой
-- `subject_change_delivery_columns_integration_test.go`.
--
-- Первичный ключ ОСТАЁТСЯ и остаётся не по недосмотру: единственная живая
-- выборка журнала — курсор `WHERE id > $1 ORDER BY id ASC LIMIT n`, и
-- обслуживает её именно он.
--
-- ───────────────────────────────────────────────────────────────────────────
-- ЧТО ОСТАЁТСЯ
--
--   остаётся   id, subject_id, op, event_type, payload, created_at — журнал
--              целиком, его читает край курсором по id;
--   остаются   ограничения 0097 (`payload` непуст, объект, называет субъекта) и
--              754001 (словарь `op`) — они судят тело и вид события, а не
--              доставку, и снимаемых колонок не называют;
--   остаётся   триггер `subject_change_outbox_notify_trigger` — он читает
--              `NEW.id`, поэтому снятие колонок его тела не касается.
--
-- ───────────────────────────────────────────────────────────────────────────
-- ОБРАТИМОСТЬ, НАЗВАННАЯ ЧЕСТНО
--
-- Down возвращает ФОРМУ (четыре колонки и частичный индекс), но не значения:
-- восстанавливать нечего — строки несли умолчание с первого дня и никогда его
-- не покидали. `attempt_count` возвращается с тем же `NOT NULL DEFAULT 0`, что
-- и был: на непустом журнале форма без умолчания не накатилась бы вовсе.
-- Строки при этом не трогаются ни в одну сторону.

-- +goose Up

DROP INDEX IF EXISTS kacho_iam.subject_change_pending_v2_idx;

ALTER TABLE kacho_iam.subject_change_outbox DROP COLUMN IF EXISTS sent_at;
ALTER TABLE kacho_iam.subject_change_outbox DROP COLUMN IF EXISTS attempt_count;
ALTER TABLE kacho_iam.subject_change_outbox DROP COLUMN IF EXISTS last_error;
ALTER TABLE kacho_iam.subject_change_outbox DROP COLUMN IF EXISTS notified_at;

-- +goose Down

ALTER TABLE kacho_iam.subject_change_outbox ADD COLUMN IF NOT EXISTS sent_at timestamp with time zone;
ALTER TABLE kacho_iam.subject_change_outbox ADD COLUMN IF NOT EXISTS attempt_count integer DEFAULT 0 NOT NULL;
ALTER TABLE kacho_iam.subject_change_outbox ADD COLUMN IF NOT EXISTS last_error text;
ALTER TABLE kacho_iam.subject_change_outbox ADD COLUMN IF NOT EXISTS notified_at timestamp with time zone;

CREATE INDEX IF NOT EXISTS subject_change_pending_v2_idx
    ON kacho_iam.subject_change_outbox USING btree (created_at) WHERE (sent_at IS NULL);
