-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- rights_rows_carry_their_authz_revision — каждая исходная строка права несёт
-- версию прав `authz_rev` (задача PRO-Robotech/kaname#484, полоса K1; сценарии
-- NTF3-180, NTF3-181 (б), NTF3-183).
--
-- Санкция: приёмка `docs/specs/sub-phase-NTF-3-kacho-modules-notifications-acceptance.md`
-- репозитория PRO-Robotech/kacho-workspace, Р30 «Колонка версии прав» (редакция
-- 39, решения Д133 и Д134 B1), одобрена на отпечатке
-- `6e7444a4d53e7a3ebfa423f9da5420344ae6a0ed2f43ce33ff7796f8db189ae6`. Доводы там;
-- здесь — то, что нужно читателю СХЕМЫ.
--
-- =============================================================================
-- ЧТО ЭТО ЗНАЧЕНИЕ
-- =============================================================================
-- `authz_rev xid8` — идентификатор транзакции, последней ИЗМЕНИВШЕЙ ПРАВО этой
-- строки. Его читает вопрос об аудитории события с оградой: строка, чья версия
-- не видна в снимке `R_E` события (`pg_visible_in_snapshot`), изменена не раньше
-- события и адресата не даёт. Отсюда оба требования к производителю значения:
--
--   * правка права обязана двигать версию — иначе право, выданное после
--     события, открыло бы его прошлое состояние;
--   * правка, права не меняющая, двигать её НЕ должна — иначе досев старта
--     службы доступа, переписывающий строку тем же содержимым, сужал бы
--     аудиторию каждого ожидающего события.
--
-- =============================================================================
-- КТО СТАВИТ ЗНАЧЕНИЕ
-- =============================================================================
-- Триггер `BEFORE INSERT OR UPDATE`, а не умолчание столбца: умолчание
-- срабатывает только на вставке и пропускает явное значение. На INSERT версия —
-- текущая транзакция ВСЕГДА, поверх любого переданного значения; на UPDATE —
-- текущая транзакция, только если строка значимых столбцов `IS DISTINCT FROM`
-- прежней, иначе `OLD.authz_rev` (в том числе поверх явного значения в SET).
--
-- Значимые столбцы перечислены в функции КАЖДОЙ таблицы ссылками на столбцы, а
-- не именами-строками: опечатка в имени отвергается при первом исполнении
-- функции, а не превращается в сравнение NULL с NULL, молча не двигающее
-- версию никогда. Служебные столбцы (`updated_at`, `created_at`, момент
-- добавления, порядковый номер, защита от удаления, описание, имя, автор
-- выдачи, время записи и порядок записи факта) значимыми не являются. Перечень
-- значимых столбцов каждой таблицы гейт NTF3-180
-- (`internal/repohygiene` `TestAudienceFenceReadsOnlyRevisionedTables`) выводит
-- ПОВЕДЕНИЕМ триггера и печатает поимённо.
--
-- `relation_fact.source_version` — порядок записи и снятия кортежа (страж от
-- воскрешения снятого права, NTF3-184), а не содержание права: запись того же
-- кортежа с новым порядком право не меняет и версию не двигает.
--
-- Имя триггера несёт `zz_` намеренно: Postgres исполняет BEFORE-триггеры одного
-- события в порядке ИМЁН, и сравнивать `NEW` с `OLD` обязан последний из них —
-- триггер, исполненный после и переписавший значимый столбец, иначе прошёл бы
-- мимо версии. Исключение одно — `users`: последнее место там держит снятие
-- отметки подтверждения адреса (`users_email_change_drops_verification`, проба
-- Н2), и триггер версии назван так, чтобы исполняться ДО него; тот пишет только
-- отметку подтверждения — служебный столбец. Соседей после триггера версии
-- держит закрытым перечнем с доводом проба
-- `authz_rev_stamp_neighbours_integration_test.go`.
--
-- =============================================================================
-- СТРОКИ, ЛЕЖАЩИЕ ДО ЭТОЙ МИГРАЦИИ
-- =============================================================================
-- Колонка заводится с умолчанием `pg_current_xact_id()` и в той же миграции его
-- теряет. Функция стабильна, поэтому значение вычисляется ОДИН раз и ложится
-- каждой прежней строке без переписи таблицы и без единого срабатывания
-- триггеров (журнал ресурсов не получает правок, которых не было): версия
-- прежних строк — транзакция этой миграции, то есть старше любого токена,
-- снятого после неё.
--
-- =============================================================================
-- ЧЕГО ЗДЕСЬ НЕТ
-- =============================================================================
-- Объектной стороны (зеркало, рёбра предков и областей, материализованные
-- кортежи привязок): вопрос с оградой её не читает, и колонки у неё нет —
-- лишняя колонка была бы находкой того же гейта.

-- +goose Up

-- access_bindings: привязка: роль, область, выбор объектов, отношение, субъект, статус, срок.
ALTER TABLE kaname.access_bindings
  ADD COLUMN authz_rev xid8 NOT NULL DEFAULT pg_current_xact_id();
ALTER TABLE kaname.access_bindings ALTER COLUMN authz_rev DROP DEFAULT;

-- +goose StatementBegin
CREATE FUNCTION kaname.access_bindings_authz_rev_stamp() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSIF ROW(NEW.id, NEW.subject_type, NEW.subject_id, NEW.role_id, NEW.resource_type, NEW.resource_id, NEW.scope, NEW.status, NEW.expires_at, NEW.target, NEW.target_digest, NEW.granted_relation)
        IS DISTINCT FROM
        ROW(OLD.id, OLD.subject_type, OLD.subject_id, OLD.role_id, OLD.resource_type, OLD.resource_id, OLD.scope, OLD.status, OLD.expires_at, OLD.target, OLD.target_digest, OLD.granted_relation) THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSE
    NEW.authz_rev := OLD.authz_rev;
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER access_bindings_zz_authz_rev_trg
  BEFORE INSERT OR UPDATE ON kaname.access_bindings
  FOR EACH ROW EXECUTE FUNCTION kaname.access_bindings_authz_rev_stamp();

-- access_binding_subjects: субъект привязки и область, которую он несёт.
ALTER TABLE kaname.access_binding_subjects
  ADD COLUMN authz_rev xid8 NOT NULL DEFAULT pg_current_xact_id();
ALTER TABLE kaname.access_binding_subjects ALTER COLUMN authz_rev DROP DEFAULT;

-- +goose StatementBegin
CREATE FUNCTION kaname.access_binding_subjects_authz_rev_stamp() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSIF ROW(NEW.binding_id, NEW.subject_type, NEW.subject_id, NEW.resource_type, NEW.resource_id)
        IS DISTINCT FROM
        ROW(OLD.binding_id, OLD.subject_type, OLD.subject_id, OLD.resource_type, OLD.resource_id) THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSE
    NEW.authz_rev := OLD.authz_rev;
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER access_binding_subjects_zz_authz_rev_trg
  BEFORE INSERT OR UPDATE ON kaname.access_binding_subjects
  FOR EACH ROW EXECUTE FUNCTION kaname.access_binding_subjects_authz_rev_stamp();

-- role_verb: глагол роли.
ALTER TABLE kaname.role_verb
  ADD COLUMN authz_rev xid8 NOT NULL DEFAULT pg_current_xact_id();
ALTER TABLE kaname.role_verb ALTER COLUMN authz_rev DROP DEFAULT;

-- +goose StatementBegin
CREATE FUNCTION kaname.role_verb_authz_rev_stamp() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSIF ROW(NEW.role_id, NEW.object_type, NEW.verb)
        IS DISTINCT FROM
        ROW(OLD.role_id, OLD.object_type, OLD.verb) THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSE
    NEW.authz_rev := OLD.authz_rev;
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER role_verb_zz_authz_rev_trg
  BEFORE INSERT OR UPDATE ON kaname.role_verb
  FOR EACH ROW EXECUTE FUNCTION kaname.role_verb_authz_rev_stamp();

-- role_rule_selectors: правило сужения роли: модуль и тип, закреплённые имена, метки.
ALTER TABLE kaname.role_rule_selectors
  ADD COLUMN authz_rev xid8 NOT NULL DEFAULT pg_current_xact_id();
ALTER TABLE kaname.role_rule_selectors ALTER COLUMN authz_rev DROP DEFAULT;

-- +goose StatementBegin
CREATE FUNCTION kaname.role_rule_selectors_authz_rev_stamp() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSIF ROW(NEW.role_id, NEW.rule_fp, NEW.arm, NEW.object_types, NEW.resource_names, NEW.match_labels)
        IS DISTINCT FROM
        ROW(OLD.role_id, OLD.rule_fp, OLD.arm, OLD.object_types, OLD.resource_names, OLD.match_labels) THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSE
    NEW.authz_rev := OLD.authz_rev;
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER role_rule_selectors_zz_authz_rev_trg
  BEFORE INSERT OR UPDATE ON kaname.role_rule_selectors
  FOR EACH ROW EXECUTE FUNCTION kaname.role_rule_selectors_authz_rev_stamp();

-- group_members: группа и член.
ALTER TABLE kaname.group_members
  ADD COLUMN authz_rev xid8 NOT NULL DEFAULT pg_current_xact_id();
ALTER TABLE kaname.group_members ALTER COLUMN authz_rev DROP DEFAULT;

-- +goose StatementBegin
CREATE FUNCTION kaname.group_members_authz_rev_stamp() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSIF ROW(NEW.group_id, NEW.member_type, NEW.member_id)
        IS DISTINCT FROM
        ROW(OLD.group_id, OLD.member_type, OLD.member_id) THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSE
    NEW.authz_rev := OLD.authz_rev;
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER group_members_zz_authz_rev_trg
  BEFORE INSERT OR UPDATE ON kaname.group_members
  FOR EACH ROW EXECUTE FUNCTION kaname.group_members_authz_rev_stamp();

-- relation_fact: кортеж: объект, отношение, субъект, условие.
ALTER TABLE kaname.relation_fact
  ADD COLUMN authz_rev xid8 NOT NULL DEFAULT pg_current_xact_id();
ALTER TABLE kaname.relation_fact ALTER COLUMN authz_rev DROP DEFAULT;

-- +goose StatementBegin
CREATE FUNCTION kaname.relation_fact_authz_rev_stamp() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSIF ROW(NEW.object_type, NEW.object_id, NEW.relation, NEW.subject, NEW.condition_name, NEW.condition_params)
        IS DISTINCT FROM
        ROW(OLD.object_type, OLD.object_id, OLD.relation, OLD.subject, OLD.condition_name, OLD.condition_params) THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSE
    NEW.authz_rev := OLD.authz_rev;
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER relation_fact_zz_authz_rev_trg
  BEFORE INSERT OR UPDATE ON kaname.relation_fact
  FOR EACH ROW EXECUTE FUNCTION kaname.relation_fact_authz_rev_stamp();

-- accounts: владелец аккаунта и метки.
ALTER TABLE kaname.accounts
  ADD COLUMN authz_rev xid8 NOT NULL DEFAULT pg_current_xact_id();
ALTER TABLE kaname.accounts ALTER COLUMN authz_rev DROP DEFAULT;

-- +goose StatementBegin
CREATE FUNCTION kaname.accounts_authz_rev_stamp() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSIF ROW(NEW.id, NEW.owner_user_id, NEW.labels)
        IS DISTINCT FROM
        ROW(OLD.id, OLD.owner_user_id, OLD.labels) THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSE
    NEW.authz_rev := OLD.authz_rev;
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER accounts_zz_authz_rev_trg
  BEFORE INSERT OR UPDATE ON kaname.accounts
  FOR EACH ROW EXECUTE FUNCTION kaname.accounts_authz_rev_stamp();

-- projects: аккаунт проекта и метки.
ALTER TABLE kaname.projects
  ADD COLUMN authz_rev xid8 NOT NULL DEFAULT pg_current_xact_id();
ALTER TABLE kaname.projects ALTER COLUMN authz_rev DROP DEFAULT;

-- +goose StatementBegin
CREATE FUNCTION kaname.projects_authz_rev_stamp() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSIF ROW(NEW.id, NEW.account_id, NEW.labels)
        IS DISTINCT FROM
        ROW(OLD.id, OLD.account_id, OLD.labels) THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSE
    NEW.authz_rev := OLD.authz_rev;
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER projects_zz_authz_rev_trg
  BEFORE INSERT OR UPDATE ON kaname.projects
  FOR EACH ROW EXECUTE FUNCTION kaname.projects_authz_rev_stamp();

-- groups: аккаунт группы и метки.
ALTER TABLE kaname.groups
  ADD COLUMN authz_rev xid8 NOT NULL DEFAULT pg_current_xact_id();
ALTER TABLE kaname.groups ALTER COLUMN authz_rev DROP DEFAULT;

-- +goose StatementBegin
CREATE FUNCTION kaname.groups_authz_rev_stamp() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSIF ROW(NEW.id, NEW.account_id, NEW.labels)
        IS DISTINCT FROM
        ROW(OLD.id, OLD.account_id, OLD.labels) THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSE
    NEW.authz_rev := OLD.authz_rev;
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER groups_zz_authz_rev_trg
  BEFORE INSERT OR UPDATE ON kaname.groups
  FOR EACH ROW EXECUTE FUNCTION kaname.groups_authz_rev_stamp();

-- service_accounts: аккаунт, включённость и метки.
ALTER TABLE kaname.service_accounts
  ADD COLUMN authz_rev xid8 NOT NULL DEFAULT pg_current_xact_id();
ALTER TABLE kaname.service_accounts ALTER COLUMN authz_rev DROP DEFAULT;

-- +goose StatementBegin
CREATE FUNCTION kaname.service_accounts_authz_rev_stamp() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSIF ROW(NEW.id, NEW.account_id, NEW.enabled, NEW.labels)
        IS DISTINCT FROM
        ROW(OLD.id, OLD.account_id, OLD.enabled, OLD.labels) THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSE
    NEW.authz_rev := OLD.authz_rev;
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER service_accounts_zz_authz_rev_trg
  BEFORE INSERT OR UPDATE ON kaname.service_accounts
  FOR EACH ROW EXECUTE FUNCTION kaname.service_accounts_authz_rev_stamp();

-- roles: область роли, её разрешения и правила, живость, метки.
ALTER TABLE kaname.roles
  ADD COLUMN authz_rev xid8 NOT NULL DEFAULT pg_current_xact_id();
ALTER TABLE kaname.roles ALTER COLUMN authz_rev DROP DEFAULT;

-- +goose StatementBegin
CREATE FUNCTION kaname.roles_authz_rev_stamp() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSIF ROW(NEW.id, NEW.account_id, NEW.project_id, NEW.cluster_id, NEW.permissions, NEW.rules, NEW.live, NEW.labels)
        IS DISTINCT FROM
        ROW(OLD.id, OLD.account_id, OLD.project_id, OLD.cluster_id, OLD.permissions, OLD.rules, OLD.live, OLD.labels) THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSE
    NEW.authz_rev := OLD.authz_rev;
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER roles_zz_authz_rev_trg
  BEFORE INSERT OR UPDATE ON kaname.roles
  FOR EACH ROW EXECUTE FUNCTION kaname.roles_authz_rev_stamp();

-- users: аккаунт, состояние участия и метки.
ALTER TABLE kaname.users
  ADD COLUMN authz_rev xid8 NOT NULL DEFAULT pg_current_xact_id();
ALTER TABLE kaname.users ALTER COLUMN authz_rev DROP DEFAULT;

-- +goose StatementBegin
CREATE FUNCTION kaname.users_authz_rev_stamp() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSIF ROW(NEW.id, NEW.account_id, NEW.invite_status, NEW.labels)
        IS DISTINCT FROM
        ROW(OLD.id, OLD.account_id, OLD.invite_status, OLD.labels) THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSE
    NEW.authz_rev := OLD.authz_rev;
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER users_authz_rev_trg
  BEFORE INSERT OR UPDATE ON kaname.users
  FOR EACH ROW EXECUTE FUNCTION kaname.users_authz_rev_stamp();

-- +goose Down

DROP TRIGGER users_authz_rev_trg ON kaname.users;
DROP FUNCTION kaname.users_authz_rev_stamp();
ALTER TABLE kaname.users DROP COLUMN authz_rev;

DROP TRIGGER roles_zz_authz_rev_trg ON kaname.roles;
DROP FUNCTION kaname.roles_authz_rev_stamp();
ALTER TABLE kaname.roles DROP COLUMN authz_rev;

DROP TRIGGER service_accounts_zz_authz_rev_trg ON kaname.service_accounts;
DROP FUNCTION kaname.service_accounts_authz_rev_stamp();
ALTER TABLE kaname.service_accounts DROP COLUMN authz_rev;

DROP TRIGGER groups_zz_authz_rev_trg ON kaname.groups;
DROP FUNCTION kaname.groups_authz_rev_stamp();
ALTER TABLE kaname.groups DROP COLUMN authz_rev;

DROP TRIGGER projects_zz_authz_rev_trg ON kaname.projects;
DROP FUNCTION kaname.projects_authz_rev_stamp();
ALTER TABLE kaname.projects DROP COLUMN authz_rev;

DROP TRIGGER accounts_zz_authz_rev_trg ON kaname.accounts;
DROP FUNCTION kaname.accounts_authz_rev_stamp();
ALTER TABLE kaname.accounts DROP COLUMN authz_rev;

DROP TRIGGER relation_fact_zz_authz_rev_trg ON kaname.relation_fact;
DROP FUNCTION kaname.relation_fact_authz_rev_stamp();
ALTER TABLE kaname.relation_fact DROP COLUMN authz_rev;

DROP TRIGGER group_members_zz_authz_rev_trg ON kaname.group_members;
DROP FUNCTION kaname.group_members_authz_rev_stamp();
ALTER TABLE kaname.group_members DROP COLUMN authz_rev;

DROP TRIGGER role_rule_selectors_zz_authz_rev_trg ON kaname.role_rule_selectors;
DROP FUNCTION kaname.role_rule_selectors_authz_rev_stamp();
ALTER TABLE kaname.role_rule_selectors DROP COLUMN authz_rev;

DROP TRIGGER role_verb_zz_authz_rev_trg ON kaname.role_verb;
DROP FUNCTION kaname.role_verb_authz_rev_stamp();
ALTER TABLE kaname.role_verb DROP COLUMN authz_rev;

DROP TRIGGER access_binding_subjects_zz_authz_rev_trg ON kaname.access_binding_subjects;
DROP FUNCTION kaname.access_binding_subjects_authz_rev_stamp();
ALTER TABLE kaname.access_binding_subjects DROP COLUMN authz_rev;

DROP TRIGGER access_bindings_zz_authz_rev_trg ON kaname.access_bindings;
DROP FUNCTION kaname.access_bindings_authz_rev_stamp();
ALTER TABLE kaname.access_bindings DROP COLUMN authz_rev;
