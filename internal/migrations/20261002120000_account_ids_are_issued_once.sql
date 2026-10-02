-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- account_ids_are_issued_once — РЕЕСТР ВЫДАННЫХ ИДЕНТИФИКАТОРОВ АККАУНТА и
-- ПРАВИЛО ИМЕНИ ФОРМЫ ИДЕНТИФИКАТОРА (задача PRO-Robotech/kaname#549).
--
-- Санкция: приёмка
-- `docs/engineering/acceptance/account-id-may-be-supplied-at-create.md`,
-- решения Р5 и Р6, сценарии AID-14, AID-16…18 и AID-24. Доводы там; здесь — то,
-- что нужно читателю СХЕМЫ.
--
-- =============================================================================
-- ЗАЧЕМ
-- =============================================================================
-- Идентификатор аккаунта теперь может прислать администратор облака
-- (`CreateAccountRequest.id`). Пока его чеканил только генератор, повторной
-- выдачи не было лишь потому, что у генератора 85 бит случайности. Удаление
-- аккаунта физическое, и за удалённым остаются строки с его идентификатором:
-- лента операций, аудит, журнал ресурсов. Принятый повторно идентификатор
-- унаследовал бы их. Неповторяемость поэтому держит база: реестр, который
-- пополняется на каждой вставке аккаунта и не очищается удалением.
--
-- =============================================================================
-- ФОРМА — ОДНОЙ ФУНКЦИЕЙ
-- =============================================================================
-- Форма генератора — `acc` и 17 знаков его алфавита, перечисленных ЯВНО, без
-- диапазонов, с якорями и регистрозависимым сравнением. Её зовут четыре места:
-- проверка реестра, отбор триггера, отбор обратного заполнения и проверка имени.
-- Второго написания нет; паритет с `ids.IsValid` судит проба
-- `TestAccountIDFormInTheSchemaAgreesWithTheGenerator`.
--
-- Формы на самих `accounts.id` нет намеренно (Р5): прислать идентификатор
-- снаружи можно только в этой форме, генератор выдаёт только её, а
-- идентификатор неизменяем. Проверка на таблице аккаунтов судила бы лишь записи
-- в обход службы. Такая запись в реестр не попадает — это граница, и её
-- утверждает AID-18.
--
-- =============================================================================
-- ТРИГГЕР — ОБЫЧНЫЙ И РАНЬШЕ ЗАПОЛНЕНИЯ
-- =============================================================================
-- Триггер — `AFTER INSERT FOR EACH ROW`, не отложенный: конфликт с реестром
-- приходит из самой вставки, а не из фиксации, и вставка отвечает тем же
-- текстом «Account <id> already exists», что и на первичном ключе. В нём нет
-- `ON CONFLICT`: выданный идентификатор обязан ОТКАЗАТЬ вставку, а не быть
-- проглоченным. Триггера на удаление нет и ссылки на `accounts` у реестра нет.
--
-- Таблица аккаунтов захватывается первым оператором, и триггер ставится раньше
-- обратного заполнения. Вставка прежнего пода, начатая до наката, фиксируется до
-- захвата и видна заполнению; пришедшая после захвата ждёт конца наката и
-- проходит через триггер. Пропасть между ними некуда (проба
-- `TestAccountIDCreatedDuringTheRegistryRolloutLandsInTheRegistry`).
--
-- =============================================================================
-- ОБРАТНОЕ ЗАПОЛНЕНИЕ — ЧЕТЫРЕ ИСТОЧНИКА
-- =============================================================================
-- Идентификаторы формы генератора вносятся из живых аккаунтов, из ленты
-- операций (`operations.account_id`), из аудита (`audit_outbox.tenant_account_id`)
-- и из журнала ресурсов вида `account`. Значение не той формы не вносится и
-- накат не роняет.
--
-- =============================================================================
-- ПРАВИЛО ИМЕНИ — ГРОМКИЙ ОТКАЗ НА НАРУШИТЕЛЕ
-- =============================================================================
-- Имя формы идентификатора допустимо, только если равно собственному
-- идентификатору (Р6; тот же предикат в `domain.Account.Validate`). Нарушители
-- считаются ДО установки проверки; есть хоть один — накат отказывает текстом с
-- правилом и числом строк и ничего не меняет (одна транзакция). Тихо
-- переименовать данные арендатора хуже, чем остановить посадку.
--
-- =============================================================================
-- ОТКАТ — ОДНОСТОРОННИЙ ПО СОДЕРЖИМОМУ
-- =============================================================================
-- Откат снимает строение: проверку имени, триггер, реестр и функцию формы.
-- Содержимое реестра при этом теряется, и пока откат стоит, идентификатор
-- удалённого аккаунта снова можно выдать. Повторный накат восстанавливает
-- реестр из тех же четырёх источников. Это записано отступлением в
-- `docs/engineering/architecture/known-divergences.md`
-- (§ «Идентификатор аккаунта можно прислать — отступление от api-id-newid»).

-- +goose Up

LOCK TABLE kaname.accounts IN SHARE ROW EXCLUSIVE MODE;

-- +goose StatementBegin
CREATE FUNCTION kaname.account_id_has_generator_form(v text) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $$
SELECT coalesce(v ~ '^acc[0123456789abcdefghjkmnpqrstvwxyz]{17}$', false)
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.account_id_has_generator_form(text) IS
    'Форма идентификатора аккаунта, которую выдаёт генератор: acc и 17 знаков алфавита 0123456789abcdefghjkmnpqrstvwxyz. Единственное объявление формы в схеме; паритет с ids.IsValid судит проба.';

-- Нарушители правила имени — до любой правки строения.
-- +goose StatementBegin
DO $$
DECLARE
    v_violators bigint;
BEGIN
    SELECT count(*) INTO v_violators
      FROM kaname.accounts
     WHERE kaname.account_id_has_generator_form(name)
       AND name <> id;
    IF v_violators > 0 THEN
        RAISE EXCEPTION 'accounts name check: % account(s) carry a name of the account id form that is not their own id; rename them, then apply this migration', v_violators;
    END IF;
END $$;
-- +goose StatementEnd

CREATE TABLE kaname.issued_account_ids (
    id text NOT NULL,
    CONSTRAINT issued_account_ids_pkey PRIMARY KEY (id),
    CONSTRAINT issued_account_ids_id_form_check CHECK (kaname.account_id_has_generator_form(id))
);

COMMENT ON TABLE kaname.issued_account_ids IS
    'Идентификаторы аккаунта, выданные когда-либо. Пополняет только триггер на вставку аккаунта; удаление аккаунта строку не трогает. Выданный идентификатор повторно не выдаётся.';

-- +goose StatementBegin
CREATE FUNCTION kaname.issued_account_ids_record() RETURNS trigger
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

CREATE TRIGGER accounts_issued_account_ids_trg AFTER INSERT ON kaname.accounts
    FOR EACH ROW EXECUTE FUNCTION kaname.issued_account_ids_record();

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
 WHERE kaname.account_id_has_generator_form(src.id);

ALTER TABLE kaname.accounts
    ADD CONSTRAINT accounts_name_is_not_a_foreign_id
    CHECK (NOT kaname.account_id_has_generator_form(name) OR name = id);

-- +goose Down

-- Откат снимает строение в обратном порядке; содержимое реестра не
-- сохраняется — см. «ОТКАТ» в шапке.

ALTER TABLE kaname.accounts DROP CONSTRAINT accounts_name_is_not_a_foreign_id;
DROP TRIGGER accounts_issued_account_ids_trg ON kaname.accounts;
DROP FUNCTION kaname.issued_account_ids_record();
DROP TABLE kaname.issued_account_ids;
DROP FUNCTION kaname.account_id_has_generator_form(text);
