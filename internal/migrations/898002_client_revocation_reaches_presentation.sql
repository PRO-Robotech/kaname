-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 898002_client_revocation_reaches_presentation — отзыв ПОРОЖДАЕТ отсечку, а не
-- только перестаёт выдавать (задача #898, приёмка F2 §2.10, сценарий F2-32).
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ
--
-- Контроль, действующий на ВЫДАЧЕ и не действующий на ПРЕДЪЯВЛЕНИИ, отзывом не
-- является: он лишь не выдаёт нового, а выданное продолжает проходить до
-- истечения срока. Это состояние НЕ СХОДИТСЯ САМО — в отличие от задержки
-- распространения, у которой есть предел, — и окно закрывает только срок
-- токена, величина которого от нагрузки не зависит.
--
-- Читатель отсечки на пути запроса заведён (миграция 897002 и авторитет отзыва
-- поверх неё), и второй ключ — клиент — он тоже читает. ПРОИЗВОДИТЕЛЯ у отсечки
-- не было НИ ОДНОГО: единственный писатель таблицы не звался из прод-кода
-- нигде. То есть механизм присутствовал целиком и не срабатывал ни разу — и
-- невидимо, потому что «работает» и «не отозвано» выглядят одинаково.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ СХЕМОЙ, А НЕ ПИСАТЕЛЕМ В КОДЕ
--
-- Три довода, каждый самостоятельно достаточный.
--
-- 1. СТРОКУ КЛИЕНТА СНИМАЕТ НЕ ТОЛЬКО ГЛАГОЛ ОТЗЫВА. Клиенты пользовательского
--    токена связаны с участием человека внешним ключом с каскадным удалением:
--    снятие участия снимает и их. Писатель, поставленный в глагол отзыва, этот
--    путь не покрывает вовсе — и не покрывает молча.
--
-- 2. ОТСЕЧКА ОБЯЗАНА БЫТЬ НЕДЕЛИМА СО СВОИМ ПОВОДОМ. Пара «снять строку» и
--    «записать отсечку» двумя операторами оставляет окно, в котором строки уже
--    нет, а выданные ею токены ещё действительны; сорвавшаяся вторая половина
--    даёт это состояние навсегда. Инвариант внутри сервиса держит оператор
--    базы, а не память автора (ban #10).
--
-- 3. ПЕРЕЧЕНЬ ОБЯЗАННЫХ ПИСАТЬ — ЭТО СПИСОК, КОТОРЫЙ РАСХОДИТСЯ С ДЕРЕВОМ. Здесь
--    производство привязано к САМОМУ ПОВОДУ, поэтому следующий путь, снимающий
--    строку или снимающий владельца, попадёт под него by construction, ничего о
--    нём не зная.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧТО ЗАПИСЫВАЕТСЯ В «КЕМ РЕШЕНО» — И ПОЧЕМУ ЭТО НЕ АНОНИМНОСТЬ
--
-- Ограничение таблицы требует непустого «кем решено», и мотив у него верный:
-- действие такой цены не бывает безымянным. Отсечка, однако, — не решение, а
-- ЕГО СЛЕДСТВИЕ: решение приняли там, где сняли строку или сняли владельца, и
-- имя принявшего записано журналом того глагола вместе с самим действием.
-- Поэтому здесь называется МЕХАНИЗМ, породивший следствие, — по нему отсечку
-- отличают от поставленной руками и находят её повод. Записать сюда чьё-то имя
-- значило бы назвать автором того, кто этой строки не писал.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ОБЛАСТЬ: ДВА ПОВОДА, И ТРЕТИЙ ЗАКРЫТ ФОРМОЙ СРОКА
--
-- Отзыв ключа клиента ⇒ запись, ключуемая КЛИЕНТОМ: выданный токен несёт
-- идентификатор клиента, и читатель резолвит по нему.
-- Перевод владельца в не-ACTIVE ⇒ запись, ключуемая СУБЪЕКТОМ: субъектом
-- выданного токена стоит владелец.
-- Истечение срока клиента не порождает НИЧЕГО и не должно: срок выдаваемого
-- токена не превышает остатка срока клиента, поэтому токенов, переживших
-- клиента, не существует и читать на предъявлении нечего.
--
-- Снятие самого принципала доходит до отсечки ЧЕРЕЗ снятие его клиентов:
-- клиенты человека уходят каскадом, а клиенты служебной учётки держат её
-- внешним ключом с запретом удаления, поэтому учётка не исчезает, пока они
-- живы. Отдельного повода это не требует — оно и есть первый.

-- +goose Up

-- ── 1. Отзыв ключа клиента: строка реестра снята ─────────────────────────────
--
-- Оператор ОДИН и монотонный: `GREATEST` не даёт границе уехать назад, иначе
-- повтор вернул бы к жизни уже отозванное. Это выражено самим оператором, а не
-- проверкой-перед-записью: под конкуренцией «прочитать, сравнить, записать»
-- даёт откат границы.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kacho_iam.minted_cutoff_on_client_removal() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO kacho_iam.minted_token_revocations (subject, revoke_before, reason, revoked_by)
    VALUES (OLD.id, now(), 'client key revoked: registry row removed', 'kacho_iam:client-key-revoked')
    ON CONFLICT (subject) DO UPDATE
       SET revoke_before = GREATEST(kacho_iam.minted_token_revocations.revoke_before, EXCLUDED.revoke_before),
           reason        = EXCLUDED.reason,
           revoked_by    = EXCLUDED.revoked_by,
           updated_at    = now();
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER user_oauth_client_removal_cuts_minted_tokens
    AFTER DELETE ON kacho_iam.user_oauth_clients
    FOR EACH ROW EXECUTE FUNCTION kacho_iam.minted_cutoff_on_client_removal();
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER sa_oauth_client_removal_cuts_minted_tokens
    AFTER DELETE ON kacho_iam.service_account_oauth_clients
    FOR EACH ROW EXECUTE FUNCTION kacho_iam.minted_cutoff_on_client_removal();
-- +goose StatementEnd

-- ── 2. Владелец переведён в не-ACTIVE ────────────────────────────────────────
--
-- Условие срабатывания стоит в самом объявлении (`WHEN`), а не внутри тела: оно
-- отсекает правки, не меняющие состояния, до вызова функции — то есть
-- обыкновенная правка строки не платит ни за что и не оставляет следа.
--
-- Переход берётся ИЗ `ACTIVE`, а не «в любое не-ACTIVE»: у владельца, который
-- ещё ни разу не был активен, токенов не существует, и отсечка для него была бы
-- записью без предмета.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kacho_iam.minted_cutoff_on_owner_deactivation() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO kacho_iam.minted_token_revocations (subject, revoke_before, reason, revoked_by)
    VALUES (NEW.id, now(), 'owner is no longer active', 'kacho_iam:owner-deactivated')
    ON CONFLICT (subject) DO UPDATE
       SET revoke_before = GREATEST(kacho_iam.minted_token_revocations.revoke_before, EXCLUDED.revoke_before),
           reason        = EXCLUDED.reason,
           revoked_by    = EXCLUDED.revoked_by,
           updated_at    = now();
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER user_deactivation_cuts_minted_tokens
    AFTER UPDATE OF invite_status ON kacho_iam.users
    FOR EACH ROW
    WHEN (OLD.invite_status = 'ACTIVE' AND NEW.invite_status <> 'ACTIVE')
    EXECUTE FUNCTION kacho_iam.minted_cutoff_on_owner_deactivation();
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER service_account_deactivation_cuts_minted_tokens
    AFTER UPDATE OF enabled ON kacho_iam.service_accounts
    FOR EACH ROW
    WHEN (OLD.enabled AND NOT NEW.enabled)
    EXECUTE FUNCTION kacho_iam.minted_cutoff_on_owner_deactivation();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS service_account_deactivation_cuts_minted_tokens ON kacho_iam.service_accounts;
DROP TRIGGER IF EXISTS user_deactivation_cuts_minted_tokens ON kacho_iam.users;
DROP TRIGGER IF EXISTS sa_oauth_client_removal_cuts_minted_tokens ON kacho_iam.service_account_oauth_clients;
DROP TRIGGER IF EXISTS user_oauth_client_removal_cuts_minted_tokens ON kacho_iam.user_oauth_clients;
DROP FUNCTION IF EXISTS kacho_iam.minted_cutoff_on_owner_deactivation();
DROP FUNCTION IF EXISTS kacho_iam.minted_cutoff_on_client_removal();
-- +goose StatementEnd
