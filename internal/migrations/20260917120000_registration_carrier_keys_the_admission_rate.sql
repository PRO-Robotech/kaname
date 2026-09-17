-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- registration_carrier_keys_the_admission_rate — НОСИТЕЛЬ КЛЮЧА ТЕМПА заведения
-- аккаунтов объявлен заново для нашей полосы (фаза Ф4, задача
-- PRO-Robotech/kacho#1270).
--
-- Санкция: одобренная Ф4
-- (`docs/engineering/acceptance/registration-and-its-three-consequences.md`,
-- решение Р5, сценарии Ф4-12, Ф4-17; §0.2 — объём СВЕРХ §5 одобренной Ф1,
-- названный вслух). Доводы там; здесь — то, что нужно читателю СХЕМЫ.
--
-- =============================================================================
-- ЧТО МЕНЯЕТСЯ — ТОЛЬКО НОСИТЕЛЬ КЛЮЧА, И ТОЛЬКО У НАШЕЙ ПОЛОСЫ
-- =============================================================================
-- Триггер `accounts_rate_admission` (миграция 0001) считает заведения аккаунтов
-- одной личностью за окно ОДНИМ оператором: переход окна и списание — одно
-- выражение, ветвь первой вставки безусловна. Ключом служил `users.external_id`
-- — идентификатор у чужого поставщика.
--
-- На полосе `own` поставщика нет; идентичность чеканит регистрация с головой
-- `own:` (F4d Р10), и она СВЕЖАЯ у каждого заведения. Ключ по ней означал бы
-- окно на одно заведение — рубеж, который не отказывает никогда и исчез бы
-- МОЛЧА. Носителем нашей полосы объявляется то, чем человек представился при
-- регистрации, — адрес, приведённый к нижнему регистру (тот же ключ, которым
-- судится занятость адреса, `users_identity_email_uniq`).
--
-- Полоса поставщика ключуется по-прежнему его идентификатором: чужой ключ не
-- тронут, и это утверждает интеграционная проба обеими строками окна.
--
-- Голова `own:` — второе написание константы `domain.OwnLaneSubjectHead`;
-- согласие держит проба `TestOwnLaneSubjectHeadAgreesWithTheSchema`.
--
-- Всё прочее в теле функции — дословно из 0001: авторитет читается первым, его
-- отсутствие — отдельный отказ (KQ005), окно полно — KQ004.
--
-- =============================================================================
-- ПОЧЕМУ ЗАМЕЩЕНИЕ ФУНКЦИИ, А НЕ ПРАВКА 0001
-- =============================================================================
-- Применённую миграцию не правят (ban #5): мигратор сверяет версию, а не
-- содержимое. Замещение тела функции — единственный способ доехать до баз, где
-- 0001 уже применена; объявление триггера не трогается — он зовёт функцию по
-- имени.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.kacho_admission_rate_count() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_kind     text := TG_ARGV[0];
    v_identity text;
    v_max      bigint;
    v_window   bigint;
BEGIN
    -- Носитель ключа: у нашей полосы (голова `own:`) — адрес в нижнем регистре,
    -- у полосы поставщика — его идентификатор (Ф4 Р5).
    SELECT CASE WHEN u.external_id LIKE 'own:%' THEN lower(u.email) ELSE u.external_id END
      INTO v_identity
      FROM kaname.users u
     WHERE u.id = NEW.owner_user_id;

    -- Владелец БЕЗ личности — законное состояние схемы (строка в состоянии
    -- приглашения внешнего идентификатора не несёт), и такой аккаунт не считается
    -- ни объёмом, ни темпом. Решение здесь то же и по той же причине: счётчик не
    -- вправе запрещать состояния, которых схема не запрещает.
    IF v_identity IS NULL OR v_identity = '' THEN
        RETURN NULL;
    END IF;

    -- Авторитет читается ПЕРВЫМ: его отсутствие — отдельный исход, а не «сколько
    -- угодно». Не названная величина означает отказ, как и у объёма.
    SELECT max_events, window_seconds INTO v_max, v_window
      FROM kaname.account_admission_rate_limits
     WHERE withdrawn_at IS NULL AND kind = v_kind;

    IF NOT FOUND THEN
        PERFORM kaname.kacho_rate_refuse(v_identity, v_kind);
        RETURN NULL;
    END IF;

    -- ЕДИНСТВЕННЫЙ оператор, принимающий решение (см. 0001): ветвь ВСТАВКИ —
    -- первое заведение носителя — проходит безусловно; ветвь ПРАВКИ берёт
    -- блокировку строки, переход окна и списание считаются одним выражением.
    INSERT INTO kaname.identity_admission_windows AS w
        (carrier_id, kind, window_started_at, admitted)
    VALUES (v_identity, v_kind, now(), 1)
    ON CONFLICT (carrier_id, kind) DO UPDATE
       SET window_started_at = CASE
               WHEN now() >= w.window_started_at + make_interval(secs => v_window)
               THEN now() ELSE w.window_started_at END,
           admitted = CASE
               WHEN now() >= w.window_started_at + make_interval(secs => v_window)
               THEN 1 ELSE w.admitted + 1 END,
           updated_at = now()
     WHERE CASE
               WHEN now() >= w.window_started_at + make_interval(secs => v_window)
               THEN 1 ELSE w.admitted + 1 END <= v_max;

    IF FOUND THEN
        RETURN NULL;
    END IF;

    -- Ноль строк означает ровно одно: окно полно.
    PERFORM kaname.kacho_rate_refuse(v_identity, v_kind);
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.kacho_admission_rate_count() IS
  'charges one admission of the current window, in the same transaction as the account row. The carrier is what the person presented: the provider subject on the provider lane, the lower-cased address on our own lane (external_id with the own: head). The first ever admission of a carrier goes through the INSERT branch and is therefore unconditional: a rate refusal on first registration would be a refusal to register. Refusals come from kacho_rate_refuse';

COMMENT ON COLUMN kaname.identity_admission_windows.carrier_id IS
  'what the person presented: the external login subject (users.external_id) on the provider lane, lower(users.email) on our own lane (external_id with the own: head) — the same carrier the volume ceiling counts by; a user row is a membership and would hand out the bypass';

-- +goose Down

-- Откат возвращает тело функции из 0001 (ключ — только внешний идентификатор).
-- Строки окна, заведённые по адресу, остаются: они безвредны — новый ключ их
-- не находит, и первое заведение по прежнему ключу пройдёт ветвью вставки.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.kacho_admission_rate_count() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_kind     text := TG_ARGV[0];
    v_identity text;
    v_max      bigint;
    v_window   bigint;
BEGIN
    SELECT u.external_id INTO v_identity
      FROM kaname.users u
     WHERE u.id = NEW.owner_user_id;

    IF v_identity IS NULL OR v_identity = '' THEN
        RETURN NULL;
    END IF;

    SELECT max_events, window_seconds INTO v_max, v_window
      FROM kaname.account_admission_rate_limits
     WHERE withdrawn_at IS NULL AND kind = v_kind;

    IF NOT FOUND THEN
        PERFORM kaname.kacho_rate_refuse(v_identity, v_kind);
        RETURN NULL;
    END IF;

    INSERT INTO kaname.identity_admission_windows AS w
        (carrier_id, kind, window_started_at, admitted)
    VALUES (v_identity, v_kind, now(), 1)
    ON CONFLICT (carrier_id, kind) DO UPDATE
       SET window_started_at = CASE
               WHEN now() >= w.window_started_at + make_interval(secs => v_window)
               THEN now() ELSE w.window_started_at END,
           admitted = CASE
               WHEN now() >= w.window_started_at + make_interval(secs => v_window)
               THEN 1 ELSE w.admitted + 1 END,
           updated_at = now()
     WHERE CASE
               WHEN now() >= w.window_started_at + make_interval(secs => v_window)
               THEN 1 ELSE w.admitted + 1 END <= v_max;

    IF FOUND THEN
        RETURN NULL;
    END IF;

    PERFORM kaname.kacho_rate_refuse(v_identity, v_kind);
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.kacho_admission_rate_count() IS
  'charges one admission of the current window, in the same transaction as the account row. The first ever admission of an identity goes through the INSERT branch and is therefore unconditional: a rate refusal on first login would be a refusal to log in. Refusals come from kacho_rate_refuse';

COMMENT ON COLUMN kaname.identity_admission_windows.carrier_id IS
  'the external login subject (users.external_id), the same carrier the volume ceiling counts by — a user row is a membership and would hand out the bypass';
