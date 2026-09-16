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
-- изменением; всё прочее в нём — дословно свод. Тела остальных четырёх зовут
-- только функции, чьё имя не меняется (`kacho_quota_refuse` — см. ниже), и не
-- трогаются.
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
    SELECT u.external_id INTO v_identity
      FROM kaname.users u
     WHERE u.id = NEW.owner_user_id;

    -- Владелец БЕЗ личности — законное состояние схемы (строка в состоянии
    -- приглашения внешнего идентификатора не несёт), и такой аккаунт не считается
    -- ни объёмом, ни темпом. Решение здесь то же и по той же причине: счётчик не
    -- вправе запрещать состояния, которых схема не запрещает. Молчаливым оно не
    -- является — предупреждение об этом уже производит триггер объёма, и второе
    -- на то же событие было бы шумом.
    IF v_identity IS NULL OR v_identity = '' THEN
        RETURN NULL;
    END IF;

    -- Авторитет читается ПЕРВЫМ: его отсутствие — отдельный исход, а не «сколько
    -- угодно». Не названная величина означает отказ, как и у объёма: «не сказано»
    -- на пути безопасности читается закрыто.
    SELECT max_events, window_seconds INTO v_max, v_window
      FROM kaname.account_admission_rate_limits
     WHERE withdrawn_at IS NULL AND kind = v_kind;

    IF NOT FOUND THEN
        PERFORM kaname.rate_refuse(v_identity, v_kind);
        RETURN NULL;
    END IF;

    -- ЕДИНСТВЕННЫЙ оператор, принимающий решение.
    --
    -- Ветвь ВСТАВКИ — первое заведение этой личности: проходит безусловно, до
    -- всякого сравнения с величиной. Это и есть «первый вход не ломается».
    --
    -- Ветвь ПРАВКИ берёт блокировку строки, поэтому второй писатель ждёт коммита
    -- первого и видит его результат: гонку разрешает база, а не порядок. Переход
    -- в следующее окно и списание считаются ОДНИМ выражением — посчитать «истекло
    -- ли окно» отдельно значило бы вернуть check-then-act через границу оператора.
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

    -- `FOUND` после INSERT истинно, когда затронута хотя бы одна строка: и на
    -- ветви вставки, и на ветви правки, чьё условие выполнилось. Ноль строк
    -- означает ровно одно — правка отвергнута условием, то есть окно полно.
    IF FOUND THEN
        RETURN NULL;
    END IF;

    -- Ноль строк означает ровно одно: окно полно. Это не check-then-act —
    -- решение уже принято атомарным оператором выше, а производитель отказа лишь
    -- облекает случившееся в контракт.
    PERFORM kaname.rate_refuse(v_identity, v_kind);
    RETURN NULL;
END;
$$;


--
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.admission_rate_count() IS 'charges one admission of the current window, in the same transaction as the account row. The first ever admission of an identity goes through the INSERT branch and is therefore unconditional: a rate refusal on first login would be a refusal to log in. Refusals come from rate_refuse';

-- +goose Down
-- Обратный ход возвращает ИМЕННО то, что завёл прямой: прежние имена и прежнее
-- тело счётчика темпа — дословно свод, включая вызов отказа под прежним именем.
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
    SELECT u.external_id INTO v_identity
      FROM kaname.users u
     WHERE u.id = NEW.owner_user_id;

    -- Владелец БЕЗ личности — законное состояние схемы (строка в состоянии
    -- приглашения внешнего идентификатора не несёт), и такой аккаунт не считается
    -- ни объёмом, ни темпом. Решение здесь то же и по той же причине: счётчик не
    -- вправе запрещать состояния, которых схема не запрещает. Молчаливым оно не
    -- является — предупреждение об этом уже производит триггер объёма, и второе
    -- на то же событие было бы шумом.
    IF v_identity IS NULL OR v_identity = '' THEN
        RETURN NULL;
    END IF;

    -- Авторитет читается ПЕРВЫМ: его отсутствие — отдельный исход, а не «сколько
    -- угодно». Не названная величина означает отказ, как и у объёма: «не сказано»
    -- на пути безопасности читается закрыто.
    SELECT max_events, window_seconds INTO v_max, v_window
      FROM kaname.account_admission_rate_limits
     WHERE withdrawn_at IS NULL AND kind = v_kind;

    IF NOT FOUND THEN
        PERFORM kaname.kacho_rate_refuse(v_identity, v_kind);
        RETURN NULL;
    END IF;

    -- ЕДИНСТВЕННЫЙ оператор, принимающий решение.
    --
    -- Ветвь ВСТАВКИ — первое заведение этой личности: проходит безусловно, до
    -- всякого сравнения с величиной. Это и есть «первый вход не ломается».
    --
    -- Ветвь ПРАВКИ берёт блокировку строки, поэтому второй писатель ждёт коммита
    -- первого и видит его результат: гонку разрешает база, а не порядок. Переход
    -- в следующее окно и списание считаются ОДНИМ выражением — посчитать «истекло
    -- ли окно» отдельно значило бы вернуть check-then-act через границу оператора.
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

    -- `FOUND` после INSERT истинно, когда затронута хотя бы одна строка: и на
    -- ветви вставки, и на ветви правки, чьё условие выполнилось. Ноль строк
    -- означает ровно одно — правка отвергнута условием, то есть окно полно.
    IF FOUND THEN
        RETURN NULL;
    END IF;

    -- Ноль строк означает ровно одно: окно полно. Это не check-then-act —
    -- решение уже принято атомарным оператором выше, а производитель отказа лишь
    -- облекает случившееся в контракт.
    PERFORM kaname.kacho_rate_refuse(v_identity, v_kind);
    RETURN NULL;
END;
$$;


--
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.kacho_admission_rate_count() IS 'charges one admission of the current window, in the same transaction as the account row. The first ever admission of an identity goes through the INSERT branch and is therefore unconditional: a rate refusal on first login would be a refusal to log in. Refusals come from kacho_rate_refuse';
