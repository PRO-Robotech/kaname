-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- resource_journal_serves_the_subscription — РЕСУРСНЫЙ ЖУРНАЛ службы доступа:
-- лента изменений семи собственных видов, которую служит общий сервер потока
-- (`corelib/subscription`).
--
-- Задача #69, APPROVED-приёмка
-- `docs/engineering/acceptance/access-resources-reach-a-narrowed-subscriber.md`
-- (§3.1 таблица, §3.2 эмиссия, §3.3 захват областей). Доводы здесь не
-- пересказываются — они там; здесь только то, что нужно читателю СХЕМЫ.
--
-- =============================================================================
-- ПОЧЕМУ ИМЯ НЕ НА `_outbox`
-- =============================================================================
-- У службы уже шесть очередей с таким окончанием (аудит, кортежи прав, почта
-- приглашений, компенсация поставщика, реконсиляция ресурса, смена субъекта), и
-- ни одна лентой изменений не является. Разделённость держится не соглашением, а
-- ограничениями: слово этого журнала не проходит в их `CHECK`, а их слова — сюда.
--
-- =============================================================================
-- ПОЧЕМУ ТРИГГЕР, А НЕ ВЫЗОВ В КАЖДОМ МЕСТЕ ЗАПИСИ
-- =============================================================================
-- Писателей семи ресурсов — пятьдесят, и сверх них те же таблицы пишут посев,
-- применение каталога модулей и применение ролей. Явная эмиссия означала бы
-- полсотни с лишним точек, каждая обязана быть в транзакции мутации, а
-- пропущенная теряет событие МОЛЧА. Триггер исполняется в транзакции своего
-- оператора by construction, какой бы она ни была, включая неявную транзакцию
-- одиночного UPDATE.
--
-- =============================================================================
-- ПОЧЕМУ СНЯТИЕ ЭМИТИТСЯ `BEFORE`, А ОСТАЛЬНОЕ `AFTER`
-- =============================================================================
-- Область предмета выводится ИЗ ЕГО СОБСТВЕННОЙ СТРОКИ и из строк, которые
-- каскад уносит вместе с ней. До снятия мир ещё тот, из которого область
-- выводится; после — уже нет. Внешний ключ принадлежностей ОТЛОЖЕННЫЙ, каскад
-- срабатывает на фиксации, поэтому `BEFORE DELETE` на `users` видит их целыми.
--
-- Обработчик снятия обязан вернуть OLD: `BEFORE`-триггер, вернувший NULL, ОТМЕНЯЕТ
-- операцию. Здесь это было бы не «событие не записалось», а «ресурс не удалился».

-- +goose Up

CREATE TABLE kaname.resource_journal (
  -- Номер выдаёт счётчик на ВСТАВКЕ, а строка становится видимой на ФИКСАЦИИ:
  -- порядок номеров и порядок фиксаций независимы. Границу устоявшегося держит
  -- общий сервер потока, а не эта таблица.
  sequence_no   BIGSERIAL    PRIMARY KEY,
  -- Вид предмета СЛОВОМ ЖУРНАЛА. Здесь оно совпадает с типом объекта модели
  -- прав, и это не случайность: словарь видов подписки обязан быть словарём
  -- типов модели, иначе вопрос о видимости строки задать нечем.
  resource_kind TEXT         NOT NULL,
  resource_id   TEXT         NOT NULL,
  -- Проектный якорь КОЛОНКОЙ и НАСТОЯЩИЙ: пусто означает «предмет проекту не
  -- принадлежит», как того требует контракт подписки. Аккаунт сюда не кладётся
  -- НИКОГДА — это была бы ложь на проводе, и молчаливая.
  project_id    TEXT         NOT NULL DEFAULT '',
  -- НАБОР захваченных областей: массив пар «тип, идентификатор». Набор, а не
  -- значение, потому что человек состоит в нескольких аккаунтах.
  scope         JSONB        NOT NULL DEFAULT '[]'::jsonb,
  event_type    TEXT         NOT NULL,
  payload       JSONB        NOT NULL,
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),

  CONSTRAINT resource_journal_event_type_check
    CHECK (event_type = ANY (ARRAY['CREATED'::text, 'UPDATED'::text, 'DELETED'::text])),
  -- Словарь видов ЗАКРЫТ вставкой, а не обнаруживается подписчиком: строка с
  -- видом вне словаря не имеет типа объекта модели прав, поэтому не доставляется,
  -- и потеря эта тихая.
  CONSTRAINT resource_journal_resource_kind_check
    CHECK (resource_kind = ANY (ARRAY[
      'account'::text, 'project'::text, 'iam_user'::text, 'iam_group'::text,
      'iam_service_account'::text, 'iam_role'::text, 'iam_access_binding'::text])),
  CONSTRAINT resource_journal_payload_object_ck
    CHECK (jsonb_typeof(payload) = 'object'::text),
  CONSTRAINT resource_journal_scope_array_ck
    CHECK (jsonb_typeof(scope) = 'array'::text)
);

-- Частичный индекс: строки без якоря по нему не отбираются никогда, и держать их
-- в нём значило бы платить за то, что не читается.
CREATE INDEX resource_journal_project_idx
  ON kaname.resource_journal (project_id, sequence_no)
  WHERE project_id <> '';

-- Обслуживает вопрос клиента подписки «какие из этих идентификаторов — снятия».
CREATE INDEX resource_journal_kind_id_idx
  ON kaname.resource_journal (resource_kind, resource_id, sequence_no);

-- +goose StatementBegin
-- Пробуждение потока. Канал назван ОТДЕЛЬНО от таблицы: имя таблицы
-- схемо-квалифицировано, а `pg_notify` квалифицированного имени не принимает.
CREATE FUNCTION kaname.resource_journal_notify() RETURNS trigger
  LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_notify('kaname_resource_journal', NEW.sequence_no::text);
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER resource_journal_notify_trg
  AFTER INSERT ON kaname.resource_journal
  FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_notify();

-- +goose StatementBegin
-- ОБЛАСТИ ПРЕДМЕТА на миг эмиссии — ровно те, что вывело бы представление
-- `kaname.resource_scope_edge`, но взятые из самой строки, а не из него: в
-- `BEFORE DELETE` представление уже отвечает о мире без этой строки.
--
-- Роль уровня КЛАСТЕРА ветви в представлении не имеет вовсе; её область берётся
-- из колонки напрямую, иначе набор у системной роли пустовал бы.
CREATE FUNCTION kaname.resource_journal_scope(p_kind text, p_row jsonb)
  RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE
  v_out jsonb := '[]'::jsonb;
BEGIN
  IF p_kind = 'account' THEN
    SELECT COALESCE(jsonb_agg(jsonb_build_object('type', 'cluster', 'id', c.id)
                              ORDER BY c.id), '[]'::jsonb)
      INTO v_out FROM kaname.clusters c;

  ELSIF p_kind = 'project' THEN
    IF COALESCE(p_row->>'account_id', '') <> '' THEN
      v_out := jsonb_build_array(
        jsonb_build_object('type', 'account', 'id', p_row->>'account_id'));
    END IF;

  ELSIF p_kind = 'iam_user' THEN
    -- Набор, а не значение: уникальна ПАРА (человек, аккаунт).
    SELECT COALESCE(jsonb_agg(jsonb_build_object('type', 'account', 'id', m.account_id)
                              ORDER BY m.account_id), '[]'::jsonb)
      INTO v_out
      FROM kaname.memberships m
     WHERE m.user_id = p_row->>'id' AND COALESCE(m.account_id, '') <> '';

  ELSIF p_kind IN ('iam_group', 'iam_service_account') THEN
    IF COALESCE(p_row->>'account_id', '') <> '' THEN
      v_out := jsonb_build_array(
        jsonb_build_object('type', 'account', 'id', p_row->>'account_id'));
    END IF;

  ELSIF p_kind = 'iam_role' THEN
    -- Область ровно одна: `roles_definition_tier_xor` это и означает.
    IF COALESCE(p_row->>'cluster_id', '') <> '' THEN
      v_out := jsonb_build_array(
        jsonb_build_object('type', 'cluster', 'id', p_row->>'cluster_id'));
    ELSIF COALESCE(p_row->>'account_id', '') <> '' THEN
      v_out := jsonb_build_array(
        jsonb_build_object('type', 'account', 'id', p_row->>'account_id'));
    ELSIF COALESCE(p_row->>'project_id', '') <> '' THEN
      v_out := jsonb_build_array(
        jsonb_build_object('type', 'project', 'id', p_row->>'project_id'));
    END IF;

  ELSIF p_kind = 'iam_access_binding' THEN
    IF lower(COALESCE(p_row->>'resource_type', '')) IN ('project', 'account', 'cluster')
       AND COALESCE(p_row->>'resource_id', '') <> '' THEN
      v_out := jsonb_build_array(jsonb_build_object(
        'type', lower(p_row->>'resource_type'), 'id', p_row->>'resource_id'));
    END IF;
  END IF;

  RETURN v_out;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
-- ПРОЕКТНЫЙ ЯКОРЬ — только настоящий проект, и только у видов, у которых он есть.
CREATE FUNCTION kaname.resource_journal_project(p_kind text, p_row jsonb)
  RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN p_kind = 'project'            THEN COALESCE(p_row->>'id', '')
    WHEN p_kind = 'iam_role'           THEN COALESCE(p_row->>'project_id', '')
    WHEN p_kind = 'iam_access_binding'
         AND lower(COALESCE(p_row->>'resource_type', '')) = 'project'
                                       THEN COALESCE(p_row->>'resource_id', '')
    ELSE ''
  END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
-- ЭМИССИЯ. Один обработчик на три операции: три почти одинаковые функции были бы
-- тремя местами, расходящимися молча. Вид приходит параметром.
--
-- НАГРУЗКА — только идентификатор. Состояния этот журнал не производит (§2.6
-- приёмки), и `to_jsonb(NEW)` утащил бы в него каждую колонку, включая
-- добавленную позже. Следствие названо вслух: заводя колонку в любой из семи
-- таблиц, о нагрузке думать не нужно.
CREATE FUNCTION kaname.resource_journal_emit() RETURNS trigger
  LANGUAGE plpgsql AS $$
DECLARE
  v_kind  text := TG_ARGV[0];
  v_event text;
  v_json  jsonb;
BEGIN
  IF TG_OP = 'DELETE' THEN
    v_event := 'DELETED';
    v_json  := to_jsonb(OLD);
  ELSIF TG_OP = 'UPDATE' THEN
    v_event := 'UPDATED';
    v_json  := to_jsonb(NEW);
  ELSE
    v_event := 'CREATED';
    v_json  := to_jsonb(NEW);
  END IF;

  INSERT INTO kaname.resource_journal
    (resource_kind, resource_id, project_id, scope, event_type, payload)
  VALUES (
    v_kind,
    v_json->>'id',
    kaname.resource_journal_project(v_kind, v_json),
    kaname.resource_journal_scope(v_kind, v_json),
    v_event,
    jsonb_build_object('id', v_json->>'id'));

  -- BEFORE-триггер, вернувший NULL, ОТМЕНИЛ БЫ снятие. AFTER-триггеру возврат
  -- безразличен, и NULL там — обычная форма.
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
-- ЭМИССИЯ ПОДТАБЛИЦ СОСТАВА: смена состава наблюдаема арендатором как ПРАВКА
-- ВЛАДЕЛЬЦА, а не как отдельный предмет — своего типа в модели прав у состава
-- нет, и спросить о видимости его строки нечем.
--
-- Владелец берётся из колонки-ссылки, названной параметром, и его строка
-- читается ЗАНОВО: нагрузка и область обязаны описывать владельца, а не состав.
CREATE FUNCTION kaname.resource_journal_emit_member() RETURNS trigger
  LANGUAGE plpgsql AS $$
DECLARE
  v_kind   text := TG_ARGV[0];
  v_col    text := TG_ARGV[1];
  v_table  text := TG_ARGV[2];
  v_row    jsonb;
  v_owner  text;
  v_ownrow jsonb;
BEGIN
  v_row := CASE WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
  v_owner := v_row->>v_col;
  IF COALESCE(v_owner, '') = '' THEN
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NULL END;
  END IF;

  EXECUTE format('SELECT to_jsonb(t) FROM kaname.%I t WHERE t.id = $1', v_table)
    INTO v_ownrow USING v_owner;

  -- Владельца уже нет: его собственное снятие эмитится своим триггером, а состав
  -- уносит каскад. Второе событие о том же снятии было бы дублем.
  IF v_ownrow IS NULL THEN
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NULL END;
  END IF;

  INSERT INTO kaname.resource_journal
    (resource_kind, resource_id, project_id, scope, event_type, payload)
  VALUES (
    v_kind,
    v_owner,
    kaname.resource_journal_project(v_kind, v_ownrow),
    kaname.resource_journal_scope(v_kind, v_ownrow),
    'UPDATED',
    jsonb_build_object('id', v_owner));

  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NULL END;
END;
$$;
-- +goose StatementEnd

-- Триггеры семи основных таблиц.
--
-- Правка эмитится ТОЛЬКО при изменении существа: повторное применение посева и
-- каталога модулей переписывает строки теми же значениями на каждом подъёме, и
-- без этого сужения каждый подъём рождал бы шторм правок, в которых ничего не
-- изменилось. Сужение по ВСЕЙ строке, а не по перечню колонок: перечень пришлось
-- бы править при каждом `ADD COLUMN`, и он бы отстал молча.

CREATE TRIGGER accounts_resource_journal_insert_trg AFTER INSERT ON kaname.accounts
  FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_emit('account');
CREATE TRIGGER accounts_resource_journal_update_trg AFTER UPDATE ON kaname.accounts
  FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION kaname.resource_journal_emit('account');
CREATE TRIGGER accounts_resource_journal_delete_trg BEFORE DELETE ON kaname.accounts
  FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_emit('account');

CREATE TRIGGER projects_resource_journal_insert_trg AFTER INSERT ON kaname.projects
  FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_emit('project');
CREATE TRIGGER projects_resource_journal_update_trg AFTER UPDATE ON kaname.projects
  FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION kaname.resource_journal_emit('project');
CREATE TRIGGER projects_resource_journal_delete_trg BEFORE DELETE ON kaname.projects
  FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_emit('project');

CREATE TRIGGER users_resource_journal_insert_trg AFTER INSERT ON kaname.users
  FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_emit('iam_user');
CREATE TRIGGER users_resource_journal_update_trg AFTER UPDATE ON kaname.users
  FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION kaname.resource_journal_emit('iam_user');
CREATE TRIGGER users_resource_journal_delete_trg BEFORE DELETE ON kaname.users
  FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_emit('iam_user');

CREATE TRIGGER groups_resource_journal_insert_trg AFTER INSERT ON kaname.groups
  FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_emit('iam_group');
CREATE TRIGGER groups_resource_journal_update_trg AFTER UPDATE ON kaname.groups
  FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION kaname.resource_journal_emit('iam_group');
CREATE TRIGGER groups_resource_journal_delete_trg BEFORE DELETE ON kaname.groups
  FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_emit('iam_group');

CREATE TRIGGER service_accounts_resource_journal_insert_trg AFTER INSERT ON kaname.service_accounts
  FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_emit('iam_service_account');
CREATE TRIGGER service_accounts_resource_journal_update_trg AFTER UPDATE ON kaname.service_accounts
  FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION kaname.resource_journal_emit('iam_service_account');
CREATE TRIGGER service_accounts_resource_journal_delete_trg BEFORE DELETE ON kaname.service_accounts
  FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_emit('iam_service_account');

CREATE TRIGGER roles_resource_journal_insert_trg AFTER INSERT ON kaname.roles
  FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_emit('iam_role');
CREATE TRIGGER roles_resource_journal_update_trg AFTER UPDATE ON kaname.roles
  FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION kaname.resource_journal_emit('iam_role');
CREATE TRIGGER roles_resource_journal_delete_trg BEFORE DELETE ON kaname.roles
  FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_emit('iam_role');

CREATE TRIGGER access_bindings_resource_journal_insert_trg AFTER INSERT ON kaname.access_bindings
  FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_emit('iam_access_binding');
CREATE TRIGGER access_bindings_resource_journal_update_trg AFTER UPDATE ON kaname.access_bindings
  FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION kaname.resource_journal_emit('iam_access_binding');
CREATE TRIGGER access_bindings_resource_journal_delete_trg BEFORE DELETE ON kaname.access_bindings
  FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_emit('iam_access_binding');

-- Триггеры трёх подтаблиц состава.
CREATE TRIGGER group_members_resource_journal_trg
  AFTER INSERT OR DELETE ON kaname.group_members
  FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_emit_member('iam_group', 'group_id', 'groups');

CREATE TRIGGER memberships_resource_journal_trg
  AFTER INSERT OR DELETE ON kaname.memberships
  FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_emit_member('iam_user', 'user_id', 'users');

CREATE TRIGGER access_binding_subjects_resource_journal_trg
  AFTER INSERT OR DELETE ON kaname.access_binding_subjects
  FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_emit_member('iam_access_binding', 'binding_id', 'access_bindings');

-- +goose Down
--
-- ЧТО ТЕРЯЕТСЯ И НЕ ВОССТАНОВИТСЯ: журнал уходит вместе с таблицей, а с ним и
-- позиции подписчиков. Повторное применение заведёт ПУСТОЙ журнал, и подписчик,
-- возобновляющийся с сохранённой позиции, получит отказ «позиция утрачена» —
-- это верный исход, а не поломка: молчаливое начало с ближайшего удержанного
-- места он записал бы как «изменений не было».

DROP TRIGGER IF EXISTS access_binding_subjects_resource_journal_trg ON kaname.access_binding_subjects;
DROP TRIGGER IF EXISTS memberships_resource_journal_trg ON kaname.memberships;
DROP TRIGGER IF EXISTS group_members_resource_journal_trg ON kaname.group_members;

DROP TRIGGER IF EXISTS access_bindings_resource_journal_delete_trg ON kaname.access_bindings;
DROP TRIGGER IF EXISTS access_bindings_resource_journal_update_trg ON kaname.access_bindings;
DROP TRIGGER IF EXISTS access_bindings_resource_journal_insert_trg ON kaname.access_bindings;
DROP TRIGGER IF EXISTS roles_resource_journal_delete_trg ON kaname.roles;
DROP TRIGGER IF EXISTS roles_resource_journal_update_trg ON kaname.roles;
DROP TRIGGER IF EXISTS roles_resource_journal_insert_trg ON kaname.roles;
DROP TRIGGER IF EXISTS service_accounts_resource_journal_delete_trg ON kaname.service_accounts;
DROP TRIGGER IF EXISTS service_accounts_resource_journal_update_trg ON kaname.service_accounts;
DROP TRIGGER IF EXISTS service_accounts_resource_journal_insert_trg ON kaname.service_accounts;
DROP TRIGGER IF EXISTS groups_resource_journal_delete_trg ON kaname.groups;
DROP TRIGGER IF EXISTS groups_resource_journal_update_trg ON kaname.groups;
DROP TRIGGER IF EXISTS groups_resource_journal_insert_trg ON kaname.groups;
DROP TRIGGER IF EXISTS users_resource_journal_delete_trg ON kaname.users;
DROP TRIGGER IF EXISTS users_resource_journal_update_trg ON kaname.users;
DROP TRIGGER IF EXISTS users_resource_journal_insert_trg ON kaname.users;
DROP TRIGGER IF EXISTS projects_resource_journal_delete_trg ON kaname.projects;
DROP TRIGGER IF EXISTS projects_resource_journal_update_trg ON kaname.projects;
DROP TRIGGER IF EXISTS projects_resource_journal_insert_trg ON kaname.projects;
DROP TRIGGER IF EXISTS accounts_resource_journal_delete_trg ON kaname.accounts;
DROP TRIGGER IF EXISTS accounts_resource_journal_update_trg ON kaname.accounts;
DROP TRIGGER IF EXISTS accounts_resource_journal_insert_trg ON kaname.accounts;

DROP FUNCTION IF EXISTS kaname.resource_journal_emit_member();
DROP FUNCTION IF EXISTS kaname.resource_journal_emit();
DROP FUNCTION IF EXISTS kaname.resource_journal_project(text, jsonb);
DROP FUNCTION IF EXISTS kaname.resource_journal_scope(text, jsonb);

DROP TRIGGER IF EXISTS resource_journal_notify_trg ON kaname.resource_journal;
DROP FUNCTION IF EXISTS kaname.resource_journal_notify();
DROP TABLE IF EXISTS kaname.resource_journal;
