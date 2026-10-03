-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- subject_cutoff_writes_both_records_under_one_lock — схемные писатели второй
-- записи отсечки получают замок по моменту (задача PRO-Robotech/kaname#335,
-- стадия S1).
--
-- Санкция: одобренная приёмка
-- `docs/engineering/acceptance/subject-cutoff-writes-both-records-under-one-lock.md`,
-- редакция 2, SHA-256
-- `b72c19f1385d9824733363d10f0032f7fa0f17b012d3acf75bf633ae991f7a5e`
-- (событие одобрения
-- https://github.com/PRO-Robotech/kaname/issues/336#issuecomment-5969140689;
-- §3 Р1, Р5; сценарии KN-SCL-01…06, 19). Доводы там; здесь — то, что нужно
-- читателю СХЕМЫ.
--
-- =============================================================================
-- ЗАМОК (Р1)
-- =============================================================================
-- Вторую запись отсечки (`kaname.minted_token_revocations`) пишут Go-дверь и две
-- функции схемы, которые зовут четыре триггера. Момент монотонен у всех
-- (`GREATEST`). Причина, решивший и `updated_at` переписываются тогда и только
-- тогда, когда входящий момент не меньше стоящего; на равных стоит последняя
-- запись. Это тот же замок, что у оператора двери (`upsertMintedCutoffSQL`,
-- `internal/repo/kaname/pg/minted_token_revocation_repo.go`): одна операция
-- записи — один замок. Проигравший момент не переносит на стоящую запись ни
-- своей причины, ни своего решившего.
--
-- =============================================================================
-- ПОЧЕМУ НОВАЯ МИГРАЦИЯ, А НЕ ПРАВКА ПРИМЕНЁННОЙ
-- =============================================================================
-- Прежние определения функций ставит `0001_initial.sql`. Правка применённого
-- файла не доезжает до базы, где он уже применён: мигратор сверяет версию, а не
-- содержимое (ban #5). Безусловная перезапись остаётся в его тексте как история
-- прежнего определения; откат (Р5) возвращает её дословно.
--
-- Триггеры не пересоздаются: они зовут функции по имени, и `CREATE OR REPLACE`
-- меняет поведение всех четырёх сразу.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.minted_cutoff_on_client_removal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO kaname.minted_token_revocations (subject, revoke_before, reason, revoked_by)
    VALUES (OLD.id, now(), 'client key revoked: registry row removed', 'kaname:client-key-revoked')
    ON CONFLICT (subject) DO UPDATE
       SET revoke_before = GREATEST(kaname.minted_token_revocations.revoke_before, EXCLUDED.revoke_before),
           reason        = CASE WHEN EXCLUDED.revoke_before >= kaname.minted_token_revocations.revoke_before
                                THEN EXCLUDED.reason ELSE kaname.minted_token_revocations.reason END,
           revoked_by    = CASE WHEN EXCLUDED.revoke_before >= kaname.minted_token_revocations.revoke_before
                                THEN EXCLUDED.revoked_by ELSE kaname.minted_token_revocations.revoked_by END,
           updated_at    = CASE WHEN EXCLUDED.revoke_before >= kaname.minted_token_revocations.revoke_before
                                THEN now() ELSE kaname.minted_token_revocations.updated_at END;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.minted_cutoff_on_owner_deactivation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO kaname.minted_token_revocations (subject, revoke_before, reason, revoked_by)
    VALUES (NEW.id, now(), 'owner is no longer active', 'kaname:owner-deactivated')
    ON CONFLICT (subject) DO UPDATE
       SET revoke_before = GREATEST(kaname.minted_token_revocations.revoke_before, EXCLUDED.revoke_before),
           reason        = CASE WHEN EXCLUDED.revoke_before >= kaname.minted_token_revocations.revoke_before
                                THEN EXCLUDED.reason ELSE kaname.minted_token_revocations.reason END,
           revoked_by    = CASE WHEN EXCLUDED.revoke_before >= kaname.minted_token_revocations.revoke_before
                                THEN EXCLUDED.revoked_by ELSE kaname.minted_token_revocations.revoked_by END,
           updated_at    = CASE WHEN EXCLUDED.revoke_before >= kaname.minted_token_revocations.revoke_before
                                THEN now() ELSE kaname.minted_token_revocations.updated_at END;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- +goose Down

-- Р5: функциям возвращается определение, действовавшее до наката
-- (`0001_initial.sql`), дословно. Строк откат не трогает.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.minted_cutoff_on_client_removal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO kaname.minted_token_revocations (subject, revoke_before, reason, revoked_by)
    VALUES (OLD.id, now(), 'client key revoked: registry row removed', 'kaname:client-key-revoked')
    ON CONFLICT (subject) DO UPDATE
       SET revoke_before = GREATEST(kaname.minted_token_revocations.revoke_before, EXCLUDED.revoke_before),
           reason        = EXCLUDED.reason,
           revoked_by    = EXCLUDED.revoked_by,
           updated_at    = now();
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.minted_cutoff_on_owner_deactivation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO kaname.minted_token_revocations (subject, revoke_before, reason, revoked_by)
    VALUES (NEW.id, now(), 'owner is no longer active', 'kaname:owner-deactivated')
    ON CONFLICT (subject) DO UPDATE
       SET revoke_before = GREATEST(kaname.minted_token_revocations.revoke_before, EXCLUDED.revoke_before),
           reason        = EXCLUDED.reason,
           revoked_by    = EXCLUDED.revoked_by,
           updated_at    = now();
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
