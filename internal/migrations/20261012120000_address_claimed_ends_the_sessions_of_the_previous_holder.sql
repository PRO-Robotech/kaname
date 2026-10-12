-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- address_claimed_ends_the_sessions_of_the_previous_holder — переход записи с
-- неподтверждённым адресом к владельцу ящика снимает записи сессии причиной
-- `address-claimed` (задача PRO-Robotech/kaname#458).
--
-- Санкция: одобренная приёмка
-- `docs/engineering/acceptance/unverified-address-passes-to-the-mailbox-owner.md`,
-- SHA-256
-- `b52c2960ce878b1d4ed755360a9167e00880d65180ce3f4cf0679c5da87076a5`
-- (запись `docs/specs/reviews/unverified-address-passes-to-the-mailbox-owner/b52c2960ce878b1d4ed755360a9167e00880d65180ce3f4cf0679c5da87076a5.yaml`,
-- `APPROVED`, событие
-- https://github.com/PRO-Robotech/kaname/issues/458#issuecomment-6110377442;
-- решение Р7, сценарий A458-10). Доводы там; здесь — то, что нужно читателю
-- СХЕМЫ. Применённые миграции не правятся: ограничение снимается и
-- объявляется заново под ТЕМ ЖЕ именем.
--
-- =============================================================================
-- ПРИЧИНА КОНЦА СЕССИИ `address-claimed` (Р7)
-- =============================================================================
-- Транзакция перехода записи снимает все записи сессии записи и ставит отсечку
-- этой причиной. Лежащих строк накат не трогает. Словарь переобъявляется
-- ЦЕЛИКОМ, поэтому список — последнее объявление (`20261008120000`,
-- kaname#669, слово `access-key-revoked`) плюс своё слово; откат возвращает
-- ровно то последнее объявление. Причина отсечки
-- (`user_token_revocations.reason`) словарём не ограничена — только длиной, —
-- и правки не требует.

-- +goose Up

LOCK TABLE kaname.human_sessions IN ACCESS EXCLUSIVE MODE;
ALTER TABLE kaname.human_sessions
    DROP CONSTRAINT human_sessions_ended_reason_check;
ALTER TABLE kaname.human_sessions
    ADD CONSTRAINT human_sessions_ended_reason_check
        CHECK (((ended_reason IS NULL) OR (ended_reason = ANY (ARRAY['logout'::text, 'password-change'::text, 'second-factor-removed'::text, 'admin-force-logout'::text, 'email-verified'::text, 'ended-from-another-session'::text, 'email-changed'::text, 'access-key-revoked'::text, 'address-claimed'::text]))));

-- +goose Down

-- Откат переводит строки, снятые переходом записи, в `logout`: различение
-- теряется, факт и момент снятия — нет (форма отката `20260927190000`).
LOCK TABLE kaname.human_sessions IN ACCESS EXCLUSIVE MODE;
UPDATE kaname.human_sessions SET ended_reason = 'logout' WHERE ended_reason = 'address-claimed';
ALTER TABLE kaname.human_sessions
    DROP CONSTRAINT human_sessions_ended_reason_check;
ALTER TABLE kaname.human_sessions
    ADD CONSTRAINT human_sessions_ended_reason_check
        CHECK (((ended_reason IS NULL) OR (ended_reason = ANY (ARRAY['logout'::text, 'password-change'::text, 'second-factor-removed'::text, 'admin-force-logout'::text, 'email-verified'::text, 'ended-from-another-session'::text, 'email-changed'::text, 'access-key-revoked'::text]))));
