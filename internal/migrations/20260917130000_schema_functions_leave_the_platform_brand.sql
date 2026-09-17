-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- schema_functions_leave_the_platform_brand — пять СОБСТВЕННЫХ функций схемы
-- перестают называть платформу:
--
--   kacho_labels_valid(jsonb)          → labels_valid
--   kacho_quota_count()                → quota_count
--   kacho_quota_carrier_lifecycle()    → quota_carrier_lifecycle
--   kacho_admission_rate_count()       → admission_rate_count
--   kacho_rate_refuse(text, text)      → rate_refuse
--
-- Задача продукта kacho#2076, предикат готовности C, п. 3 («в схеме … чужого
-- бренда ноль»); строка оси «таблицы» переписи осей службы
-- (`internal/supplyhygiene/platform_name_axes_test.go`) называла эти пять
-- остатком и предписывала переименование новой миграцией. Держатель —
-- `internal/migrations/schema_functions_leave_the_brand_integration_test.go`.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ИМЯ БЕЗ ПРИСТАВКИ, А НЕ С ПРИСТАВКОЙ СЛУЖБЫ
--
-- Функция живёт в схеме `kaname` — квалификатор уже называет продукт, и
-- приставка повторяла бы его. Так названы остальные функции схемы
-- (`iam_rules_valid`, `resource_journal_emit`, `limits_scope_ref_exists`),
-- и так решён тот же вопрос у имён посевной идентичности: имя называет
-- УСТАНОВКУ, а не продукт (приёмка `seed-identity-names-its-own-service.md`
-- §2.3).
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ПЕРЕИМЕНОВАНИЕ, А НЕ СНЯТИЕ И ЗАВЕДЕНИЕ ЗАНОВО
--
-- На четыре из пяти функций ссылаются объекты схемы: десять ограничений
-- CHECK на проверке меток, шесть триггеров на трёх других. Объект ссылается на
-- функцию ИДЕНТИФИКАТОРОМ, поэтому `ALTER FUNCTION … RENAME TO` оставляет
-- каждую ссылку на месте by construction; снятие с заведением заново потребовало
-- бы снять и завести все шестнадцать зависимых, и любой пропущенный потерялся бы
-- молча. Что зависимые указывают на переименованную, держатель сверяет числом
-- по графу свода, а не предполагает.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ОДНО ТЕЛО ПЕРЕПИСЫВАЕТСЯ, И ЭТО НЕСУЩЕЕ
--
-- Вызов внутри тела plpgsql разрешается ПРИ ИСПОЛНЕНИИ по имени, а не по
-- идентификатору: счётчик темпа зовёт отказ темпа строкой `kacho_rate_refuse`,
-- и после переименования отказа эта строка означала бы «функции нет» на первом
-- же входе, который окно отвергает. Поэтому тело счётчика переписывается тем же
-- изменением; всё прочее в нём — дословно Ф4 (`20260917120000`, kacho#1270):
-- носитель ключа нашей полосы — адрес в нижнем регистре, полосы поставщика —
-- его идентификатор. Тела остальных четырёх зовут только функции, чьё имя не
-- меняется (`kacho_quota_refuse` — см. ниже), и не трогаются.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ НОМЕР СТОИТ ПОСЛЕ Ф4, А НЕ ПО ЧАСАМ ЗАВЕДЕНИЯ
--
-- Ф4 замещает тело счётчика темпа ПО ИМЕНИ (`CREATE OR REPLACE FUNCTION
-- kaname.kacho_admission_rate_count()`). Переименование, идущее РАНЬШЕ Ф4,
-- оставило бы триггеру функцию с прежним телом (он держит её идентификатором),
-- а Ф4 завела бы под именем платформы вторую, осиротевшую, зовущую отказ по
-- имени, которого уже нет. Ключ носителя терялся бы МОЛЧА — ни один накат не
-- отказал бы. Поэтому переименование обязано идти последним из тех, что
-- замещают эти тела, и его тело — тело Ф4. Держит это KAN-FN-03 (тело
-- счётчика после цепочки несёт голову нашей полосы) и
-- `TestOwnLaneSubjectHeadAgreesWithTheSchema` (голова в этом накате — та же,
-- что чеканит производитель).
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧЕГО ЭТА МИГРАЦИЯ НЕ ДЕЛАЕТ — НАЗВАНО, ЧТОБЫ НЕ ИСКАЛИ
--
--   * `kacho_quota_refuse` и `kacho_quota_admit` НЕ переименовывает. Обе
--     отрисованы шаблоном фундамента (corelib `quota/refusal.sql.tmpl`) одним
--     текстом на шесть владельцев; их имя выбирает шаблон, и решение «остаться»
--     принято отдельно (kacho#2538). Расхождение этого решения с п. 3 предиката
--     поднято владельцу; здесь они стоят в ведомости решённого остаться
--     держателя — поимённо, с доводом, самоистекающей записью;
--   * текста применённого свода не правит (ban #5): вхождения прежних имён в
--     `0001_initial.sql` и двух последующих миграциях остаются свидетельством,
--     а условие судится по ЖИВОЙ схеме;
--   * ни одной строки данных не трогает: переименование — операция над
--     каталогом, и откат его точно обратим.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ИСХОДОВ ДВА, И ВТОРОЙ — ОТКАЗ, А НЕ ТИШИНА
--
-- `ALTER FUNCTION` над отсутствующей функцией отказывает вслух, как и над
-- именем, которое уже занято. Молчаливого «переписывать нечего» здесь нет
-- намеренно: цепочка линейна, и состояние «уже переименовано» до этой версии
-- недостижимо; получить его можно только рукой в базе, а о чужой руке миграция
-- обязана сказать, а не подстроиться.

-- +goose Up
ALTER FUNCTION kaname.kacho_labels_valid(jsonb) RENAME TO labels_valid;
ALTER FUNCTION kaname.kacho_quota_count() RENAME TO quota_count;
ALTER FUNCTION kaname.kacho_quota_carrier_lifecycle() RENAME TO quota_carrier_lifecycle;
ALTER FUNCTION kaname.kacho_rate_refuse(text, text) RENAME TO rate_refuse;
ALTER FUNCTION kaname.kacho_admission_rate_count() RENAME TO admission_rate_count;

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

-- +goose Down
-- Обратный ход возвращает ИМЕННО то, что завёл прямой: прежние имена и прежнее
-- тело счётчика темпа — дословно Ф4 (`20260917120000`), включая вызов отказа под
-- прежним именем; ключ носителя нашей полосы откат НЕ снимает — он предмет Ф4,
-- а не этой миграции.
ALTER FUNCTION kaname.admission_rate_count() RENAME TO kacho_admission_rate_count;
ALTER FUNCTION kaname.rate_refuse(text, text) RENAME TO kacho_rate_refuse;
ALTER FUNCTION kaname.quota_carrier_lifecycle() RENAME TO kacho_quota_carrier_lifecycle;
ALTER FUNCTION kaname.quota_count() RENAME TO kacho_quota_count;
ALTER FUNCTION kaname.labels_valid(jsonb) RENAME TO kacho_labels_valid;

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
