-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose NO TRANSACTION
-- +goose Up

-- =============================================================================
-- Два курсорных обхода iam без служащего индекса (задача #708)
-- =============================================================================
--
-- (A) `operations` — общий список операций
-- -----------------------------------------------------------------------------
-- Запрос строит общий `pkg/operations` (`pgRepo.listWithOwner`):
--
--     SELECT … FROM kacho_iam.operations [WHERE …]
--     ORDER BY created_at ASC, id ASC LIMIT <размер+1>
--
-- Все его фильтры необязательны (`resource_id`, `account_id`, предикат
-- владельца), поэтому ведущего равенства нет и порядок обязан приходить из
-- индекса по самим ключам курсора. `operations_created_at_idx (created_at)` из
-- `0001_initial` несёт только первый ключ, `operations_account_id_idx
-- (account_id, created_at, id) WHERE account_id IS NOT NULL` из
-- `0016_operations_account_id` — частичный и требует равенства по account_id,
-- которого у общей ветки нет.
--
-- (B) `access_bindings` — ОБРАТНЫЙ обход счёта выдач аккаунта
-- -----------------------------------------------------------------------------
-- У этой таблицы ДВА курсорных обхода с разными подписями, и это тот случай,
-- ради которого единица счёта в #708 — пара «таблица × подпись», а не таблица:
--
--     ListAccessBindings         → ORDER BY created_at ASC,  id ASC
--     ListForAccount (счёт выдач)→ ORDER BY created_at DESC, id ASC
--
-- Первый обслуживает `access_bindings_cursor_idx (created_at, id)` из
-- `0073_list_cursor_indexes`. Второму он НЕ помогает, и это не вопрос вкуса:
-- btree читается в обе стороны, обратное чтение `(created_at ASC, id ASC)` даёт
-- `created_at DESC, id DESC` — то есть НЕ ту вторичную сортировку. Смешанное
-- направление одним индексом не выражается, поэтому нужен второй, дословно
-- повторяющий обход.
--
-- Индекс, а не правка обхода: порядок страницы — часть контракта чтения
-- (свежие выдачи первыми), и менять его ради индекса значило бы менять
-- наблюдаемое поведение ради внутренней детали. Предикат продолжения у обхода
-- уже согласован с этим порядком (`created_at < $ OR (created_at = $ AND id >
-- $)`), и новый индекс выражает его диапазоном целиком.
--
-- CONCURRENTLY: обе таблицы пишутся на пути запроса (операции — на каждую
-- мутацию, выдачи — на каждый grant/revoke), останавливать их запись ради сборки
-- индекса нечем оправдать. Цена — прерванная сборка оставляет INVALID-индекс,
-- который планировщик не использует, а `IF NOT EXISTS` при повторе матчит его по
-- имени и не пересобирает; закрыто пост-условием.

-- +goose StatementBegin
DO $$
DECLARE
    idx text;
BEGIN
    FOREACH idx IN ARRAY ARRAY['operations_cursor_idx', 'access_bindings_recent_cursor_idx'] LOOP
        IF EXISTS (
            SELECT 1 FROM pg_index i
              JOIN pg_class c ON c.oid = i.indexrelid
              JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'kacho_iam' AND c.relname = idx AND NOT i.indisvalid
        ) THEN
            EXECUTE format('DROP INDEX kacho_iam.%I', idx);
        END IF;
    END LOOP;
END
$$;
-- +goose StatementEnd

CREATE INDEX CONCURRENTLY IF NOT EXISTS operations_cursor_idx
    ON kacho_iam.operations (created_at, id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS access_bindings_recent_cursor_idx
    ON kacho_iam.access_bindings (created_at DESC, id ASC);

-- +goose StatementBegin
DO $$
DECLARE
    idx text;
BEGIN
    FOREACH idx IN ARRAY ARRAY['operations_cursor_idx', 'access_bindings_recent_cursor_idx'] LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_index i
              JOIN pg_class c ON c.oid = i.indexrelid
              JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'kacho_iam' AND c.relname = idx AND i.indisvalid
        ) THEN
            RAISE EXCEPTION
                'kacho_iam.% missing or INVALID after rebuild — cursor pages of this table would sort the whole set on every request', idx;
        END IF;
    END LOOP;
END
$$;
-- +goose StatementEnd

-- +goose Down

DROP INDEX CONCURRENTLY IF EXISTS kacho_iam.operations_cursor_idx;
DROP INDEX CONCURRENTLY IF EXISTS kacho_iam.access_bindings_recent_cursor_idx;
