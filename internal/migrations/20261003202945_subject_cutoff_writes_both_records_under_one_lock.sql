-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- subject_cutoff_writes_both_records_under_one_lock — отсечка субъекта: обе
-- записи, один замок. Схемные писатели второй записи получают замок по моменту
-- (задача PRO-Robotech/kaname#335, стадия S1); всякая запись первой строки
-- той же транзакцией пишет вторую (задача PRO-Robotech/kaname#336, стадия S2).
--
-- Санкция: одобренная приёмка
-- `docs/engineering/acceptance/subject-cutoff-writes-both-records-under-one-lock.md`,
-- редакция 2, SHA-256
-- `b72c19f1385d9824733363d10f0032f7fa0f17b012d3acf75bf633ae991f7a5e`
-- (событие одобрения
-- https://github.com/PRO-Robotech/kaname/issues/336#issuecomment-5969140689;
-- §3 Р1…Р5; сценарии KN-SCL-01…13, 19). Доводы там; здесь — то, что нужно
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
--
-- =============================================================================
-- ЗЕРКАЛО ПЕРВОЙ ЗАПИСИ ВО ВТОРУЮ (Р2)
-- =============================================================================
-- Записей отсечки две, и судят по ним разные читатели: первую
-- (`kaname.user_token_revocations`) — выдача и вход, вторую — авторитет отзыва
-- на пути запроса. Go-дверь `upsertSubjectCutoff` кладёт обе, но писатель на
-- голом SQL мимо неё клал одну. Теперь это держит схема: триггер
-- `user_token_revocations_mirror_to_minted_trg` на вставке и изменении первой
-- записи той же транзакцией пишет вторую — субъект тот же `user_id`, момент и
-- причина те же, решивший — `revoked_by_user_id`, а без него имя механизма по
-- правилу двери (`'kaname:' || reason`, при пустой причине
-- `kaname:subject-cutoff`). Запись идёт под замком Р1.
--
-- Изменение, не тронувшее ни момента, ни причины, ни решившего (проигравший
-- момент у оператора двери), вторую не пишет: переносить нечего.
--
-- Отказ второй записи (её ограничения: решивший непуст и не длиннее 128
-- знаков) отвергает оператор целиком — первая не ложится одна (`23514`).
--
-- Обратного зеркала НЕТ намеренно: вторую пишет и блокировка человека, а
-- блокировка — обратимое состояние, не отсечка; перенос её в первую запись
-- сделал бы необратимым то, что `Unblock` обязан вернуть (§0.3 приёмки).
-- Удаление не зеркалится (Р3): уборка снимает вторую по своему доказательству,
-- каскад удаления человека — первую.
--
-- Порядок захвата: зеркало берёт строку второй записи после строки первой; ни
-- один писатель второй записи не берёт после неё строку первой. Цикла
-- ожидания нет (KN-SCL-11).
--
-- =============================================================================
-- ПРИВЕДЕНИЕ ЛЕЖАЩИХ СТРОК (Р4)
-- =============================================================================
-- Каждая первая запись, у которой второй нет или момент второй меньше, отдаёт
-- второй свой момент, причину и решившего. Строки, где вторая не отстаёт, и
-- вторые записи без первой не трогаются. Приведение идемпотентно: повторный
-- накат после отката не меняет ни одной строки. Оно может воссоздать вторую
-- запись, уже снятую уборкой как бессмысленную; такая строка не меняет ни
-- одного исхода, и уборка снимет её снова.
--
-- Порядок внутри наката: сперва функции и триггер, потом приведение — строка
-- первой записи, вставленная параллельно накату, уже идёт через зеркало.

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

-- +goose StatementBegin
CREATE FUNCTION kaname.user_token_revocations_mirror_to_minted() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.revoke_before = OLD.revoke_before
       AND NEW.reason = OLD.reason
       AND NEW.revoked_by_user_id IS NOT DISTINCT FROM OLD.revoked_by_user_id THEN
        RETURN NULL;
    END IF;
    INSERT INTO kaname.minted_token_revocations (subject, revoke_before, reason, revoked_by)
    VALUES (NEW.user_id, NEW.revoke_before, NEW.reason,
            COALESCE(NULLIF(NEW.revoked_by_user_id, ''),
                     CASE WHEN NEW.reason = '' THEN 'kaname:subject-cutoff'
                          ELSE 'kaname:' || NEW.reason END))
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

COMMENT ON FUNCTION kaname.user_token_revocations_mirror_to_minted() IS
    'subject cutoff: every write of the first record writes the second under the instant lock (kaname#336); one direction only';

CREATE TRIGGER user_token_revocations_mirror_to_minted_trg
    AFTER INSERT OR UPDATE ON kaname.user_token_revocations
    FOR EACH ROW EXECUTE FUNCTION kaname.user_token_revocations_mirror_to_minted();

INSERT INTO kaname.minted_token_revocations (subject, revoke_before, reason, revoked_by)
SELECT u.user_id, u.revoke_before, u.reason,
       COALESCE(NULLIF(u.revoked_by_user_id, ''),
                CASE WHEN u.reason = '' THEN 'kaname:subject-cutoff' ELSE 'kaname:' || u.reason END)
  FROM kaname.user_token_revocations u
ON CONFLICT (subject) DO UPDATE
   SET revoke_before = EXCLUDED.revoke_before,
       reason        = EXCLUDED.reason,
       revoked_by    = EXCLUDED.revoked_by,
       updated_at    = now()
 WHERE kaname.minted_token_revocations.revoke_before < EXCLUDED.revoke_before;

-- +goose Down

-- Р5: зеркало снимается. Строки, которые оно положило, остаются.
DROP TRIGGER user_token_revocations_mirror_to_minted_trg ON kaname.user_token_revocations;
DROP FUNCTION kaname.user_token_revocations_mirror_to_minted();

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
