-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- Обход уборки отсечек идёт по границе отзыва (задача #1292, приёмка
-- `retention-sweep-has-a-caller.md` §4.2).
--
-- ПРЕДМЕТ. У двух таблиц из трёх, чей рост задаёт внешний, индекс под предикат
-- уборки уже есть: `client_assertion_replay_expires_at_idx` (миграция 898001) и
-- `session_revocations_ttl_idx` (0001_initial). У отсечек его НЕТ — уборка по
-- ним шла бы полным перебором таблицы, которая ради того и убирается, что
-- растёт от внешнего темпа. Проход, стоящий тем дороже, чем больше накопилось,
-- отстаёт ровно тогда, когда он нужен.
--
-- ПОЧЕМУ НОВАЯ МИГРАЦИЯ, А НЕ ПРАВКА 897002. Та применена, а применённую
-- миграцию не правят (ban #5): правка не доехала бы ни на один поднятый стенд,
-- и «индекс объявлен» разошлось бы с «индекс существует».
--
-- ФОРМА. Предикат уборки — `revoke_before < now() - make_interval(secs => <порог>)` с
-- `ORDER BY revoke_before` и пределом партии, поэтому индекс по одной колонке
-- обслуживает и отбор, и порядок. Частичным он быть не может: границы «что уже
-- бессмысленно» в схеме нет — она вычисляется из политики токенов в момент
-- прохода, а не объявлена константой.
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS minted_token_revocations_revoke_before_idx
    ON kacho_iam.minted_token_revocations (revoke_before);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS kacho_iam.minted_token_revocations_revoke_before_idx;
-- +goose StatementEnd
