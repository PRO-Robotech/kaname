-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- account_id_is_a_client_string — ИДЕНТИФИКАТОР АККАУНТА — СТРОКА, ЗАДАННАЯ
-- КЛИЕНТОМ (задача PRO-Robotech/kaname#1052).
--
-- Санкция: приёмка
-- `docs/engineering/acceptance/account-id-may-be-supplied-at-create.md`,
-- решения Р5 и Р6а, сценарии AID-14, AID-18, AID-32, AID-33, AID-35, AID-38,
-- AID-40 и AID-41. Доводы там; здесь — то, что нужно читателю СХЕМЫ.
--
-- =============================================================================
-- ЗАЧЕМ
-- =============================================================================
-- Администратор облака задаёт идентификатор аккаунта строкой, понятной людям
-- (логин площадки потребителя), а не только формой генератора. Два правила,
-- которые держала случайность генератора, теперь держит база:
--
--   - выданный идентификатор не выдаётся повторно (Р5) — для ВСЕЙ формы
--     аккаунта, а не только для формы генератора;
--   - строка обозначает не больше одного аккаунта (Р6а): идентификатор не
--     совпадает с именем или идентификатором другого живого аккаунта, имя — с
--     идентификатором другого живого аккаунта, и совпадение судится после
--     свёртки похожих знаков (`o` → `0`, `i` и `l` → `1`). Пара «имя ↔ имя
--     другого» по-прежнему сравнивается побайтово ключом `accounts_name_unique`.
--
-- =============================================================================
-- ФОРМА АККАУНТА — НОВОЙ ФУНКЦИЕЙ, ПРЕЖНЯЯ НЕ ТРОНУТА
-- =============================================================================
-- `account_id_has_account_form` — синтаксическая часть формы Р2 (а)–(г): от 3 до
-- 30 знаков; строчные латинские буквы, цифры и дефис, перечисленные ЯВНО, без
-- диапазонов; первая — буква, последняя — буква или цифра; двух дефисов подряд
-- нет. Резерв (д) схема не судит: строка резерва через контракт в таблицу не
-- попадает, её отвергает распознаватель службы до операции. Паритет функции с
-- распознавателем службы судит проба AID-33 по таблицам AID-05/AID-06.
--
-- Прежняя `account_id_has_generator_form` НЕ расширяется: её читает и правило
-- имени Р6 (`accounts_name_is_not_a_foreign_id`). Расширенная, она сделала бы
-- недопустимым почти всякое имя, а строки, уже лежащие в таблице, нарушали бы
-- проверку молча до первой своей правки.
--
-- =============================================================================
-- РЕЕСТР ВЫДАННЫХ — ВСЯ ФОРМА АККАУНТА
-- =============================================================================
-- Проверка реестра и отбор триггера на вставку аккаунта переходят на форму
-- аккаунта; обратное заполнение повторяется по тем же четырём источникам и на
-- уже внесённых строках не отказывает. Запись в обход службы с идентификатором
-- вне формы по-прежнему в реестр не вносится — граница редакции 3, а не
-- послабление.
--
-- =============================================================================
-- ПРАВИЛО Р6а — ТАБЛИЦА СТРОК АККАУНТОВ, НЕ BEFORE-ТРИГГЕР
-- =============================================================================
-- Правило несимметрично (пары с идентификатором — после свёртки, «имя ↔ имя» —
-- побайтово), поэтому одним индексом UNIQUE на `accounts` оно не выражается.
-- Носитель — таблица `account_handles`, ключ которой — СВЁРНУТАЯ строка:
--
--   - строка идентификатора живого аккаунта — запись с `account_id`, ровно одна
--     на строку (первичный ключ): второй идентификатор и любое имя другого
--     аккаунта с той же свёрнутой строкой отвергаются ключом;
--   - строка имени — запись без `account_id` со счётом имён, которые в неё
--     свёртываются: имена разных аккаунтов одну запись делят, а на запись
--     идентификатора имя не ложится (отказ с тем же именем ключа);
--   - имя, свёртывающееся в собственный идентификатор, записи не заводит: это
--     умолчание, и собственная пара не конфликтует.
--
-- Записи ведёт триггер `AFTER INSERT OR DELETE OR UPDATE OF id, name` — после
-- строки, а не до неё. Вставка аккаунта пишет `ON CONFLICT DO NOTHING` без цели:
-- BEFORE-триггер внёс бы запись и для вставки, которую затем проглотил ключ
-- имени, и оставил бы в таблице сироту за несостоявшимся аккаунтом, а перебор
-- имени личного аккаунта той же транзакцией регистрации упирался бы в неё.
-- AFTER-триггер строки, которой нет, не видит.
--
-- Записи одной строки аккаунта трогаются в ПОРЯДКЕ СВЁРНУТЫХ СТРОК: две
-- транзакции, задевающие одни и те же строки, берут их блокировки одним
-- порядком и не встают в мёртвую взаимную блокировку. Решение принимается на
-- захваченной записи: незафиксированная запись другой транзакции сперва
-- дожидается своего исхода (ban #10 — проверки перед вставкой нет).
--
-- Только ЖИВЫЕ строки: удаление аккаунта и правка имени освобождают строку.
-- Повторную выдачу идентификатора держит реестр, а не эта таблица.
--
-- =============================================================================
-- НАРУШИТЕЛИ — ГРОМКИЙ ОТКАЗ ДО ЛЮБОЙ ПРАВКИ
-- =============================================================================
-- Живые аккаунты, чьё имя или идентификатор совпадает после свёртки с
-- идентификатором другого живого аккаунта, считаются до установки правила;
-- есть хоть один — накат отказывает текстом с правилом и числом строк и ничего
-- не меняет (одна транзакция). Ожидаемое число — 0.
--
-- Таблица аккаунтов захватывается первым оператором: вставка прежнего пода,
-- начатая до наката, фиксируется до захвата и видна заполнению; пришедшая после
-- захвата ждёт конца наката и проходит через новый триггер.
--
-- =============================================================================
-- ОТКАТ — ОДНОСТОРОННИЙ ПО СОДЕРЖИМОМУ
-- =============================================================================
-- Откат снимает правило Р6а и возвращает форму реестра к форме генератора,
-- снимая строки заданной формы. Пока откат стоит, такой идентификатор
-- удалённого аккаунта снова можно выдать; повторный накат заново заполнит реестр
-- из тех же источников. Это записано отступлением в
-- `docs/engineering/architecture/known-divergences.md` рядом с записью 22.

-- +goose Up

LOCK TABLE kaname.accounts IN SHARE ROW EXCLUSIVE MODE;

-- +goose StatementBegin
CREATE FUNCTION kaname.account_id_has_account_form(v text) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $$
SELECT coalesce(
    length(v) BETWEEN 3 AND 30
    AND v ~ '^[abcdefghijklmnopqrstuvwxyz][abcdefghijklmnopqrstuvwxyz0123456789-]*[abcdefghijklmnopqrstuvwxyz0123456789]$'
    AND strpos(v, '--') = 0,
    false)
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.account_id_has_account_form(text) IS
    'Синтаксическая часть формы идентификатора аккаунта (приёмка, Р2 (а)–(г)): 3–30 знаков; строчные латинские буквы, цифры и дефис; первая — буква, последняя — буква или цифра; без двух дефисов подряд. Резерв (д) судит распознаватель службы. Паритет с ним судит проба AID-33.';

-- +goose StatementBegin
CREATE FUNCTION kaname.account_handle_fold(v text) RETURNS text
    LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT
    AS $$
SELECT translate(v, 'oil', '011')
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.account_handle_fold(text) IS
    'Свёртка похожих знаков правила Р6а: o → 0, i и l → 1. Та же свёртка в службе — domain.FoldLookAlike; паритет судит проба.';

-- Нарушители правила Р6а — до любой правки строения.
-- +goose StatementBegin
DO $$
DECLARE
    v_violators bigint;
BEGIN
    SELECT count(*) INTO v_violators
      FROM (
            SELECT a.id
              FROM kaname.accounts a
              JOIN kaname.accounts b
                ON kaname.account_handle_fold(b.id) = kaname.account_handle_fold(a.id) AND b.id <> a.id
            UNION
            SELECT a.id
              FROM kaname.accounts a
              JOIN kaname.accounts b
                ON kaname.account_handle_fold(b.id) = kaname.account_handle_fold(a.name) AND b.id <> a.id
           ) AS v;
    IF v_violators > 0 THEN
        RAISE EXCEPTION 'accounts handle check: % account(s) carry a name or id that matches another account''s id after look-alike folding; rename or remove them, then apply this migration', v_violators;
    END IF;
END $$;
-- +goose StatementEnd

-- Реестр выданных: проверка и отбор триггера — на форму аккаунта.
ALTER TABLE kaname.issued_account_ids DROP CONSTRAINT issued_account_ids_id_form_check;
ALTER TABLE kaname.issued_account_ids
    ADD CONSTRAINT issued_account_ids_id_form_check CHECK (kaname.account_id_has_account_form(id));

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.issued_account_ids_record() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF kaname.account_id_has_account_form(NEW.id) THEN
        INSERT INTO kaname.issued_account_ids (id) VALUES (NEW.id);
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

INSERT INTO kaname.issued_account_ids (id)
SELECT src.id
  FROM (
        SELECT id FROM kaname.accounts
        UNION
        SELECT account_id FROM kaname.operations WHERE account_id IS NOT NULL
        UNION
        SELECT tenant_account_id FROM kaname.audit_outbox WHERE tenant_account_id IS NOT NULL
        UNION
        SELECT resource_id FROM kaname.resource_journal WHERE resource_kind = 'account'
       ) AS src
 WHERE kaname.account_id_has_account_form(src.id)
ON CONFLICT (id) DO NOTHING;

COMMENT ON TABLE kaname.issued_account_ids IS
    'Идентификаторы аккаунта, выданные когда-либо, во всей форме аккаунта (kaname#1052, Р5). Пополняет только триггер на вставку аккаунта; удаление аккаунта строку не трогает. Выданный идентификатор повторно не выдаётся.';

-- Правило Р6а.
CREATE TABLE kaname.account_handles (
    handle text NOT NULL,
    account_id text,
    name_count integer NOT NULL,
    CONSTRAINT account_handles_pkey PRIMARY KEY (handle),
    CONSTRAINT account_handles_holder_check CHECK (
        (account_id IS NOT NULL AND name_count = 0)
        OR (account_id IS NULL AND name_count > 0))
);

COMMENT ON TABLE kaname.account_handles IS
    'Строки живых аккаунтов после свёртки похожих знаков (kaname#1052, Р6а): запись с account_id — идентификатор, ровно один на строку; запись без account_id — имена, которые в неё свёртываются, со счётом. Ведёт только триггер на accounts.';

-- +goose StatementBegin
CREATE FUNCTION kaname.account_handles_follow() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_old_id text;
    v_old_name text;
    v_new_id text;
    v_new_name text;
    v_op record;
    v_count integer;
BEGIN
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        v_old_id := OLD.id;
        v_old_name := OLD.name;
    END IF;
    IF TG_OP IN ('UPDATE', 'INSERT') THEN
        v_new_id := NEW.id;
        v_new_name := NEW.name;
    END IF;
    IF v_old_id IS NOT DISTINCT FROM v_new_id AND v_old_name IS NOT DISTINCT FROM v_new_name THEN
        RETURN NULL;
    END IF;
    -- Каждая строка аккаунта — шаг над своей записью; шаги исполняются в
    -- порядке свёрнутых строк (и снятие раньше записи на одной строке), чтобы
    -- встречные транзакции брали блокировки одним порядком.
    FOR v_op IN
        SELECT o.handle, o.kind, o.account_id
          FROM (
                SELECT kaname.account_handle_fold(v_old_id) AS handle, 'release_id'::text AS kind,
                       v_old_id AS account_id, 0 AS step
                 WHERE v_old_id IS NOT NULL AND v_old_id IS DISTINCT FROM v_new_id
                UNION ALL
                SELECT kaname.account_handle_fold(v_old_name), 'release_name', v_old_id, 1
                 WHERE v_old_id IS NOT NULL
                   AND (v_old_id IS DISTINCT FROM v_new_id OR v_old_name IS DISTINCT FROM v_new_name)
                   AND kaname.account_handle_fold(v_old_name) <> kaname.account_handle_fold(v_old_id)
                UNION ALL
                SELECT kaname.account_handle_fold(v_new_id), 'claim_id', v_new_id, 2
                 WHERE v_new_id IS NOT NULL AND v_new_id IS DISTINCT FROM v_old_id
                UNION ALL
                SELECT kaname.account_handle_fold(v_new_name), 'claim_name', v_new_id, 3
                 WHERE v_new_id IS NOT NULL
                   AND (v_old_id IS DISTINCT FROM v_new_id OR v_old_name IS DISTINCT FROM v_new_name)
                   AND kaname.account_handle_fold(v_new_name) <> kaname.account_handle_fold(v_new_id)
               ) AS o
         ORDER BY o.handle, o.step
    LOOP
        CASE v_op.kind
        WHEN 'claim_id' THEN
            -- Ключ отвергает и второй идентификатор, и имя другого аккаунта.
            INSERT INTO kaname.account_handles (handle, account_id, name_count)
            VALUES (v_op.handle, v_op.account_id, 0);
        WHEN 'claim_name' THEN
            INSERT INTO kaname.account_handles AS h (handle, account_id, name_count)
            VALUES (v_op.handle, NULL, 1)
            ON CONFLICT (handle) DO UPDATE SET name_count = h.name_count + 1
             WHERE h.account_id IS NULL;
            IF NOT FOUND THEN
                -- Запись строки — идентификатор другого живого аккаунта; она
                -- захвачена конфликтом и зафиксирована её владельцем.
                RAISE EXCEPTION 'duplicate key value violates unique constraint "account_handles_pkey"'
                    USING ERRCODE = 'unique_violation',
                          CONSTRAINT = 'account_handles_pkey',
                          TABLE = 'account_handles',
                          SCHEMA = 'kaname',
                          DETAIL = 'the name folds into the id of another live account';
            END IF;
        WHEN 'release_id' THEN
            DELETE FROM kaname.account_handles
             WHERE handle = v_op.handle AND account_id = v_op.account_id;
        WHEN 'release_name' THEN
            SELECT name_count INTO v_count
              FROM kaname.account_handles
             WHERE handle = v_op.handle AND account_id IS NULL
               FOR UPDATE;
            IF v_count = 1 THEN
                DELETE FROM kaname.account_handles WHERE handle = v_op.handle AND account_id IS NULL;
            ELSIF v_count > 1 THEN
                UPDATE kaname.account_handles SET name_count = name_count - 1
                 WHERE handle = v_op.handle AND account_id IS NULL;
            END IF;
        END CASE;
    END LOOP;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER accounts_one_string_one_account_trg
    AFTER INSERT OR DELETE OR UPDATE OF id, name ON kaname.accounts
    FOR EACH ROW EXECUTE FUNCTION kaname.account_handles_follow();

INSERT INTO kaname.account_handles (handle, account_id, name_count)
SELECT kaname.account_handle_fold(id), id, 0 FROM kaname.accounts;

INSERT INTO kaname.account_handles (handle, account_id, name_count)
SELECT s.handle, NULL, count(*)
  FROM (
        SELECT kaname.account_handle_fold(name) AS handle, kaname.account_handle_fold(id) AS own
          FROM kaname.accounts
       ) AS s
 WHERE s.handle <> s.own
 GROUP BY s.handle;

-- +goose Down

-- Откат снимает правило Р6а и возвращает реестр к форме генератора; строки
-- заданной формы из реестра снимаются — см. «ОТКАТ» в шапке.

DROP TRIGGER accounts_one_string_one_account_trg ON kaname.accounts;
DROP FUNCTION kaname.account_handles_follow();
DROP TABLE kaname.account_handles;

DELETE FROM kaname.issued_account_ids WHERE NOT kaname.account_id_has_generator_form(id);
ALTER TABLE kaname.issued_account_ids DROP CONSTRAINT issued_account_ids_id_form_check;
ALTER TABLE kaname.issued_account_ids
    ADD CONSTRAINT issued_account_ids_id_form_check CHECK (kaname.account_id_has_generator_form(id));

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.issued_account_ids_record() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF kaname.account_id_has_generator_form(NEW.id) THEN
        INSERT INTO kaname.issued_account_ids (id) VALUES (NEW.id);
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

COMMENT ON TABLE kaname.issued_account_ids IS
    'Идентификаторы аккаунта, выданные когда-либо. Пополняет только триггер на вставку аккаунта; удаление аккаунта строку не трогает. Выданный идентификатор повторно не выдаётся.';

DROP FUNCTION kaname.account_handle_fold(text);
DROP FUNCTION kaname.account_id_has_account_form(text);
