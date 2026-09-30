-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- scope_owner_links_are_immutable — владелец аккаунта (`accounts.owner_user_id`)
-- и аккаунт проекта (`projects.account_id`) неизменяемы, и держит это БАЗА, а
-- не код писателей (задача PRO-Robotech/kaname#484).
--
-- Санкция: замысел `docs/changes/issue-2924/design.md` репозитория
-- PRO-Robotech/kacho-workspace, З23 п. 4 (CX5-10 (в)), одобрен записью ревью
-- на отпечатке `c33e4a829cfcd10b58d51d48eaeffc4659ddf296b6003bbb3d6b64a18c515305`;
-- приёмка `docs/specs/sub-phase-NTF-5-operator-notices-acceptance.md` §1.3,
-- одобрена на отпечатке
-- `367b948297cf260266223e12c62715355435ac894789f73c998b24bc35760153`.
-- Доводы там; здесь — то, что нужно читателю СХЕМЫ.
--
-- =============================================================================
-- КТО СТОИТ НА ЭТОМ СВОЙСТВЕ
-- =============================================================================
-- Кэш областей службы извещений (`notify`, таблица `notice_scope_cache`)
-- хранит ответ `DescribeScope` — аккаунт области и владельца аккаунта — БЕЗ
-- СРОКА. Смена любой из двух связей оставила бы кэш отвечать прежним
-- владельцем навсегда: письмо ушло бы не тому человеку. До этой миграции
-- неизменяемость держалась только тем, что ни один оператор правки не пишет
-- эти колонки (правка аккаунта и проекта — `name`, `description`, `labels`);
-- следующий писатель мог нарушить её молча.
--
-- =============================================================================
-- ФОРМА: AFTER UPDATE, условие на ЗНАЧЕНИЕ, а не на список колонок
-- =============================================================================
-- Замысел называет `BEFORE UPDATE OF <колонка>`. Контракт замысла сохранён —
-- смена значения отвергается кодом `23514` (`check_violation`), правка прочих
-- колонок проходит, запись тем же значением проходит. Форма взята шире по двум
-- причинам:
--
--   - `UPDATE OF <колонка>` срабатывает, только когда колонка названа в SET.
--     Смену, внесённую соседним BEFORE-триггером (сегодня таких на обеих
--     таблицах ноль), он бы пропустил. Условие WHEN на значение этого не знает.
--   - BEFORE-триггер видит строку, какой её оставили BEFORE-триггеры с именем,
--     сортирующимся РАНЬШЕ; сосед с именем ПОЗЖЕ сменил бы значение уже после
--     проверки (та же граница названа у `users_email_change_drops_verification`).
--     AFTER-триггер видит ИТОГОВУЮ строку — после всех BEFORE-триггеров и
--     после каскада внешнего ключа, — поэтому порядок имён его не касается.
--
-- Отказ в AFTER-триггере строки откатывает весь оператор, включая запись
-- журнала ресурсов (`*_resource_journal_update_trg`), сделанную тем же
-- оператором.
--
-- ГРАНИЦА, НАЗВАННАЯ ВСЛУХ. Триггер судит правку строки. Удаление аккаунта или
-- проекта и новая вставка с ТЕМ ЖЕ id этим механизмом не судятся: id выдаёт
-- приложение, повторной выдачи id нет, а удалению аккаунта с проектами мешает
-- внешний ключ `projects_account_fk ON DELETE RESTRICT`.

-- +goose Up

-- +goose StatementBegin
CREATE FUNCTION kaname.accounts_owner_user_id_immutable() RETURNS trigger
  LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'kaname.accounts.owner_user_id is immutable after create (account %): the notify service scope cache keeps the account owner without expiry and would keep answering with the previous owner', OLD.id
    USING ERRCODE = 'check_violation';
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.projects_account_id_immutable() RETURNS trigger
  LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'kaname.projects.account_id is immutable after create (project %): the notify service scope cache keeps the project account without expiry and would keep answering with the previous account', OLD.id
    USING ERRCODE = 'check_violation';
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER accounts_owner_user_id_immutable_trg
  AFTER UPDATE ON kaname.accounts
  FOR EACH ROW WHEN (OLD.owner_user_id IS DISTINCT FROM NEW.owner_user_id)
  EXECUTE FUNCTION kaname.accounts_owner_user_id_immutable();

CREATE TRIGGER projects_account_id_immutable_trg
  AFTER UPDATE ON kaname.projects
  FOR EACH ROW WHEN (OLD.account_id IS DISTINCT FROM NEW.account_id)
  EXECUTE FUNCTION kaname.projects_account_id_immutable();

COMMENT ON COLUMN kaname.accounts.owner_user_id IS
  'Владелец аккаунта. Неизменяем после создания: смену значения отвергает база (триггер accounts_owner_user_id_immutable_trg, 23514); на свойстве стоит бессрочный кэш областей службы извещений.';

COMMENT ON COLUMN kaname.projects.account_id IS
  'Аккаунт проекта. Неизменяем после создания: смену значения отвергает база (триггер projects_account_id_immutable_trg, 23514); на свойстве стоит бессрочный кэш областей службы извещений.';

-- +goose Down

DROP TRIGGER IF EXISTS projects_account_id_immutable_trg ON kaname.projects;
DROP TRIGGER IF EXISTS accounts_owner_user_id_immutable_trg ON kaname.accounts;
DROP FUNCTION IF EXISTS kaname.projects_account_id_immutable();
DROP FUNCTION IF EXISTS kaname.accounts_owner_user_id_immutable();
COMMENT ON COLUMN kaname.projects.account_id IS NULL;
COMMENT ON COLUMN kaname.accounts.owner_user_id IS NULL;
