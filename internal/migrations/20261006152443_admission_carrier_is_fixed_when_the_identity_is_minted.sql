-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- admission_carrier_is_fixed_when_the_identity_is_minted — носитель окна темпа
-- заведения у нашей полосы закрепляется в момент чеканки личности и не следует
-- за адресом (задача PRO-Robotech/kaname#197).
--
-- Санкция: приёмка `docs/engineering/acceptance/admission-rate-carrier-is-fixed-at-registration.md`
-- (отпечаток f85ce731…d394, запись
-- `docs/specs/reviews/admission-rate-carrier-is-fixed-at-registration/f85ce7312024e68d63939fbad2bd42e286846aaf03f1b6c47bd8513694ecd394.yaml`,
-- `APPROVED`, событие опубликовано в kaname#197): Р1 (носитель назначает база
-- тем же оператором, что чеканит личность), Р2 (два инварианта базы), Р3
-- (перенос окон без сброса), Р4 (полоса поставщика не тронута); сценарии
-- A197-01…09.
--
-- =============================================================================
-- ЗАЧЕМ
-- =============================================================================
-- Счётчик темпа (`admission_rate_count`, Ф4 Р5) ключевал окно нашей полосы
-- ТЕКУЩИМ `lower(users.email)`. Адрес изменяем: сменившийся адрес сменил бы
-- ключ, и следующее заведение пошло бы ветвью первой вставки — безусловно.
-- Сегодня пути смены адреса в службе нет (гейт
-- `TestPeopleAddressHasNoWriterInServiceCode`), поэтому класс латентный, и
-- закрывается он ДО появления такого пути: носитель — самостоятельное значение
-- строки человека, а не вывод из её текущего адреса.
--
-- =============================================================================
-- КАК ДЕРЖИТСЯ
-- =============================================================================
-- (1) КОЛОНКА `admission_carrier` — адрес в нижнем регистре на момент чеканки
--     личности нашей полосы; у приглашения и полосы поставщика — ''.
-- (2) ТРИГГЕР `users_admission_carrier_is_fixed` (BEFORE INSERT OR UPDATE)
--     назначает носитель САМ, когда строка получает идентичность с головой
--     `own:` (вставка регистрации либо правка приглашения при активации), —
--     писатель службы носителя не передаёт и помнить о нём не обязан. Он же
--     отвергает KQ006 правку непустого носителя на любое другое значение и
--     присланный носитель, отличный от адреса строки в нижнем регистре:
--     присланное значение база не перезаписывает молча. Имя сортируется ДО
--     `users_email_change_drops_verification`: триггеры одного вида
--     исполняются в порядке имён, а этот адреса не меняет — сосед, меняющий
--     адрес ПОСЛЕ проверки отметки, остаётся ровно один (ноль).
-- (3) ОГРАНИЧЕНИЕ `users_own_lane_admission_carrier_check` (23514): носитель
--     непуст тогда и только тогда, когда идентичность несёт голову `own:`, и
--     записан в нижнем регистре — последний рубеж за назначением (2).
-- (4) СЧЁТЧИК темпа читает носитель вместо текущего адреса. Он отложенный до
--     фиксации (`accounts_rate_admission … DEFERRABLE INITIALLY DEFERRED`):
--     строку человека он читает, когда оператор чеканки уже исполнен, в каком
--     бы порядке транзакция ни вставила аккаунт.
--
-- ПЕРЕНОС ТОЧЕН (Р3): писателей адреса в существующую строку ноль, значит
-- нынешний адрес и есть адрес при чеканке; заполнение кладёт ровно его, и уже
-- открытые окна (их ключ — тот же `lower(email)`) продолжают считаться.
-- Заполнение идёт ДО ограничения и ПОСЛЕ триггера: триггер принимает носитель,
-- равный адресу, — это и есть его второй близнец. Замок берётся на всё время
-- миграции: писатель, вставивший строку нашей полосы между заполнением и
-- ограничением, иначе отверг бы накат.
--
-- Отказы обоих инвариантов — дефект службы, а не ввод вызывающего (носитель
-- вызывающий не присылает): KQ006 отображается ветвью полосы учёта темпа
-- `pgmaperr.go`, ограничение — перепись `checkValueLanes` (полоса службы);
-- оба — `INTERNAL` с фиксированным текстом.

-- +goose Up
LOCK TABLE kaname.users IN SHARE ROW EXCLUSIVE MODE;

ALTER TABLE kaname.users ADD COLUMN admission_carrier text DEFAULT ''::text NOT NULL;

COMMENT ON COLUMN kaname.users.admission_carrier IS
  'Носитель окна темпа заведения нашей полосы (kaname#197): адрес в нижнем регистре на момент чеканки личности own:. Назначает его база (триггер users_admission_carrier_is_fixed), а не писатель; не переписывается (KQ006). У приглашения и полосы поставщика — пусто.';

-- +goose StatementBegin
CREATE FUNCTION kaname.users_admission_carrier_is_fixed() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Непустой носитель неизменяем: запись того же значения правкой не является.
    IF TG_OP = 'UPDATE' AND OLD.admission_carrier <> '' THEN
        IF NEW.admission_carrier IS DISTINCT FROM OLD.admission_carrier THEN
            RAISE EXCEPTION 'admission carrier of user % is fixed when the identity is minted', OLD.id
                USING ERRCODE = 'KQ006';
        END IF;
        RETURN NEW;
    END IF;

    -- Чеканка личности нашей полосы: вставка либо правка строки без носителя,
    -- получающей голову own:. Носитель — адрес строки в нижнем регистре;
    -- присланное иное значение — отказ, а не молчаливая замена.
    IF NEW.external_id LIKE 'own:%' THEN
        IF NEW.admission_carrier = '' THEN
            NEW.admission_carrier := lower(NEW.email);
        ELSIF NEW.admission_carrier <> lower(NEW.email) THEN
            RAISE EXCEPTION 'admission carrier of user % is fixed when the identity is minted', NEW.id
                USING ERRCODE = 'KQ006';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.users_admission_carrier_is_fixed() IS
  'assigns the admission carrier of our own lane (the lower-cased address) in the same statement that mints an own: identity, and refuses (KQ006) any rewrite of a non-empty carrier and any sent carrier that differs from the lower-cased address (kaname#197)';

CREATE TRIGGER users_admission_carrier_is_fixed
  BEFORE INSERT OR UPDATE ON kaname.users
  FOR EACH ROW EXECUTE FUNCTION kaname.users_admission_carrier_is_fixed();

-- Перенос: нынешний адрес людей нашей полосы — их адрес при чеканке (Р3).
UPDATE kaname.users
   SET admission_carrier = lower(email)
 WHERE external_id LIKE 'own:%';

ALTER TABLE kaname.users
  ADD CONSTRAINT users_own_lane_admission_carrier_check CHECK (
    ((external_id LIKE 'own:%') = (admission_carrier <> ''))
    AND admission_carrier = lower(admission_carrier)
  );

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.admission_rate_count() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_kind     text := TG_ARGV[0];
    v_identity text;
    v_max      bigint;
    v_window   bigint;
BEGIN
    -- Носитель ключа: у нашей полосы (голова `own:`) — носитель, закреплённый
    -- при чеканке личности (kaname#197), у полосы поставщика — его
    -- идентификатор (Ф4 Р5).
    SELECT CASE WHEN u.external_id LIKE 'own:%' THEN u.admission_carrier ELSE u.external_id END
      INTO v_identity
      FROM kaname.users u
     WHERE u.id = NEW.owner_user_id;

    -- Владелец БЕЗ личности — законное состояние схемы (строка в состоянии
    -- приглашения внешнего идентификатора не несёт), и такой аккаунт не считается
    -- ни объёмом, ни темпом. После kaname#197 ключ нашей полосы пуст не бывает
    -- (users_own_lane_admission_carrier_check): пустой ключ — это и только это
    -- состояние приглашения.
    IF v_identity IS NULL OR v_identity = '' THEN
        RETURN NULL;
    END IF;

    -- Авторитет читается ПЕРВЫМ: его отсутствие — отдельный исход, а не «сколько
    -- угодно». Не названная величина означает отказ, как и у объёма.
    SELECT max_events, window_seconds INTO v_max, v_window
      FROM kaname.account_admission_rate_limits
     WHERE withdrawn_at IS NULL AND kind = v_kind;

    IF NOT FOUND THEN
        PERFORM kaname.rate_refuse(v_identity, v_kind);
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
    PERFORM kaname.rate_refuse(v_identity, v_kind);
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.admission_rate_count() IS
  'charges one admission of the current window, in the same transaction as the account row. The carrier is what the person presented: the provider subject on the provider lane, and on our own lane (external_id with the own: head) the admission carrier fixed when the identity was minted (users.admission_carrier, kaname#197) — an address change does not move the window. The first ever admission of a carrier goes through the INSERT branch and is therefore unconditional: a rate refusal on first registration would be a refusal to register. Refusals come from rate_refuse';

COMMENT ON COLUMN kaname.identity_admission_windows.carrier_id IS
  'what the person presented: the external login subject (users.external_id) on the provider lane, the admission carrier fixed when the own: identity was minted (users.admission_carrier, kaname#197) on our own lane — the same carrier the volume ceiling counts by; a user row is a membership and would hand out the bypass';

-- +goose Down
-- Откат возвращает тело счётчика и его описание ДОСЛОВНО к предыдущему
-- состоянию (`20260917130000`): ключ нашей полосы — текущий `lower(email)`;
-- снимает ограничение, триггер, функцию и колонку. Окна не трогает: их ключ у
-- людей, чей адрес не менялся, совпадает с прежним.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.admission_rate_count() RETURNS trigger
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
        PERFORM kaname.rate_refuse(v_identity, v_kind);
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
    PERFORM kaname.rate_refuse(v_identity, v_kind);
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.admission_rate_count() IS
  'charges one admission of the current window, in the same transaction as the account row. The carrier is what the person presented: the provider subject on the provider lane, the lower-cased address on our own lane (external_id with the own: head). The first ever admission of a carrier goes through the INSERT branch and is therefore unconditional: a rate refusal on first registration would be a refusal to register. Refusals come from rate_refuse';

COMMENT ON COLUMN kaname.identity_admission_windows.carrier_id IS
  'what the person presented: the external login subject (users.external_id) on the provider lane, lower(users.email) on our own lane (external_id with the own: head) — the same carrier the volume ceiling counts by; a user row is a membership and would hand out the bypass';

ALTER TABLE kaname.users DROP CONSTRAINT users_own_lane_admission_carrier_check;
DROP TRIGGER users_admission_carrier_is_fixed ON kaname.users;
DROP FUNCTION kaname.users_admission_carrier_is_fixed();
ALTER TABLE kaname.users DROP COLUMN admission_carrier;
