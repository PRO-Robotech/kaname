-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- access_key_revoke_ends_the_sessions_of_the_person — снятие ключа доступа
-- снимает записи сессии человека причиной `access-key-revoked` (задача
-- PRO-Robotech/kaname#669).
--
-- Санкция: одобренная приёмка
-- `docs/engineering/acceptance/passwordless-login-with-access-key.md`,
-- SHA-256
-- `5fe6cca1aea606f96b2f24174a8f45411291f69250e6fb268b3274fd17a58af4`
-- (запись `docs/specs/reviews/passwordless-login-with-access-key/5fe6cca1aea606f96b2f24174a8f45411291f69250e6fb268b3274fd17a58af4.yaml`,
-- `APPROVED`, событие
-- https://github.com/PRO-Robotech/kaname/issues/351#issuecomment-5969017642;
-- решение Р8, сценарий Ф13-21). Доводы там; здесь — то, что нужно читателю
-- СХЕМЫ. Применённые миграции не правятся: ограничение снимается и
-- объявляется заново под ТЕМ ЖЕ именем.
--
-- =============================================================================
-- ПРИЧИНА КОНЦА СЕССИИ `access-key-revoked` (Р8)
-- =============================================================================
-- Транзакция снятия ключа снимает записи сессии человека и ставит отсечку этой
-- причиной. Лежащих строк накат не трогает. Словарь переобъявляется ЦЕЛИКОМ,
-- поэтому список — последнее объявление (`20261007150000`, kaname#635, слово
-- `email-changed`) плюс своё слово; откат возвращает ровно то последнее
-- объявление. Причина отсечки (`user_token_revocations.reason`) словарём не
-- ограничена — только длиной, — и правки не требует.

-- +goose Up

LOCK TABLE kaname.human_sessions IN ACCESS EXCLUSIVE MODE;
ALTER TABLE kaname.human_sessions
    DROP CONSTRAINT human_sessions_ended_reason_check;
ALTER TABLE kaname.human_sessions
    ADD CONSTRAINT human_sessions_ended_reason_check
        CHECK (((ended_reason IS NULL) OR (ended_reason = ANY (ARRAY['logout'::text, 'password-change'::text, 'second-factor-removed'::text, 'admin-force-logout'::text, 'email-verified'::text, 'ended-from-another-session'::text, 'email-changed'::text, 'access-key-revoked'::text]))));

-- +goose Down

-- Откат переводит строки, снятые снятием ключа, в `logout`: различение
-- теряется, факт и момент снятия — нет (форма отката `20260927190000`).
LOCK TABLE kaname.human_sessions IN ACCESS EXCLUSIVE MODE;
UPDATE kaname.human_sessions SET ended_reason = 'logout' WHERE ended_reason = 'access-key-revoked';
ALTER TABLE kaname.human_sessions
    DROP CONSTRAINT human_sessions_ended_reason_check;
ALTER TABLE kaname.human_sessions
    ADD CONSTRAINT human_sessions_ended_reason_check
        CHECK (((ended_reason IS NULL) OR (ended_reason = ANY (ARRAY['logout'::text, 'password-change'::text, 'second-factor-removed'::text, 'admin-force-logout'::text, 'email-verified'::text, 'ended-from-another-session'::text, 'email-changed'::text]))));
