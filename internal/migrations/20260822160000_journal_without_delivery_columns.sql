-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 20260822160000 — журнал намерений теряет колонки доставки: доставлять некому
-- (kacho#917).
--
-- ───────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ЭТО НЕ ДЕФЕКТ ПОВЕДЕНИЯ И ВСЁ РАВНО ЧИНИТСЯ
--
-- Дренаж, применявший строки журнала к внешнему движку отношений, снят вместе
-- с самим движком. Журнал ОСТАЛСЯ и остаётся не «на всякий случай»: прямой
-- факт, из которого собирается вердикт о доступе, складывается ИЗ ЭТИХ СТРОК
-- триггером (миграция 0098). Читает он `payload`, `event_type`, `created_at` и
-- `id` — и только их.
--
-- А `sent_at`, `attempt_count`, `last_error` не читает НИКТО. Три следствия, и
-- каждое стоит своей строки:
--
--   1. ВЕЛИЧИНА ЛЖЁТ ПО СМЫСЛУ. `sent_at IS NULL` означало «не доставлено»;
--      теперь оно означает «доставлять некому», а выглядит по-прежнему. Всякий,
--      кто спросит «сколько недоставленных», получит число, которое ничего не
--      измеряет — и примет его за отставание очереди.
--   2. ЧЕТЫРЕ ЧАСТИЧНЫХ ИНДЕКСА `WHERE sent_at IS NULL` оплачиваются КАЖДОЙ
--      вставкой, а вставка идёт на пути мутации: цена ложится на арендатора,
--      создающего ресурс. Спрашивающего у этих индексов нет ни одного.
--   3. УБОРКИ У ТАБЛИЦЫ НЕТ, и по `sent_at` её теперь не построить. Это
--      отдельный предмет и здесь НЕ решается — снятие ложных колонок его не
--      создаёт и не усугубляет, но и не закрывает: об этом сказано прямо, а не
--      умолчано.
--
-- ───────────────────────────────────────────────────────────────────────────
-- ЧТО СНИМАЕТСЯ И ЧТО ОСТАЁТСЯ
--
--   снимается  sent_at, attempt_count, last_error — величины доставки
--   снимается  четыре частичных индекса `WHERE sent_at IS NULL` (все до одного
--              обслуживали клейм дренажа: голова партиции, порядок клейма,
--              голова кортежа, ожидающие)
--   снимается  tuple_key — колонка ПОД индекс клейма, введённая миграцией 0067
--              ради разбиения партиций; партиций больше нет
--   остаётся   id, event_type, payload, created_at — всё, что читает триггер
--              свёртки, и ровно это
--
-- ───────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ИМЯ ТАБЛИЦЫ НЕ МЕНЯЕТСЯ (решение, а не забывчивость)
--
-- Имя досталось от внешнего движка, которого больше нет, и по смыслу устарело.
-- Переименование при этом стоит непропорционально дорого: таблицу пишет КАЖДАЯ
-- мутация выдачи, на ней висит триггер свёртки, и её имя названо в применённых
-- миграциях, править которые нельзя (ban #5) — совместимость пришлось бы
-- держать представлением, то есть заводить второе имя того же предмета.
--
-- Имя историческое и объяснено в одном месте — здесь. Второе имя, живущее ради
-- перехода, обошлось бы дороже, чем устаревшее слово в одном идентификаторе.

-- +goose Up

ALTER TABLE kacho_iam.fga_outbox DROP COLUMN IF EXISTS sent_at;
ALTER TABLE kacho_iam.fga_outbox DROP COLUMN IF EXISTS attempt_count;
ALTER TABLE kacho_iam.fga_outbox DROP COLUMN IF EXISTS last_error;
ALTER TABLE kacho_iam.fga_outbox DROP COLUMN IF EXISTS tuple_key;

-- Индексы уходят вместе с колонкой, на которой стоял их предикат; те, что
-- пережили бы её (ключ без sent_at), снимаются явно.
DROP INDEX IF EXISTS kacho_iam.fga_outbox_pending_idx;
DROP INDEX IF EXISTS kacho_iam.fga_outbox_partition_head_idx;
DROP INDEX IF EXISTS kacho_iam.fga_outbox_claim_order_idx;
DROP INDEX IF EXISTS kacho_iam.fga_outbox_tuple_head_idx;

-- +goose Down

ALTER TABLE kacho_iam.fga_outbox ADD COLUMN IF NOT EXISTS sent_at timestamptz;
ALTER TABLE kacho_iam.fga_outbox ADD COLUMN IF NOT EXISTS attempt_count integer DEFAULT 0 NOT NULL;
ALTER TABLE kacho_iam.fga_outbox ADD COLUMN IF NOT EXISTS last_error text;
ALTER TABLE kacho_iam.fga_outbox ADD COLUMN IF NOT EXISTS tuple_key text;

CREATE INDEX IF NOT EXISTS fga_outbox_pending_idx
    ON kacho_iam.fga_outbox (created_at) WHERE sent_at IS NULL;
CREATE INDEX IF NOT EXISTS fga_outbox_partition_head_idx
    ON kacho_iam.fga_outbox ((payload->>'object'), id) WHERE sent_at IS NULL;
CREATE INDEX IF NOT EXISTS fga_outbox_claim_order_idx
    ON kacho_iam.fga_outbox (attempt_count, id) WHERE sent_at IS NULL;
CREATE INDEX IF NOT EXISTS fga_outbox_tuple_head_idx
    ON kacho_iam.fga_outbox (tuple_key, id) WHERE sent_at IS NULL;
