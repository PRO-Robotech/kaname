-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- system_roles_carry_canonical_ids — две системные роли (`system.admin`,
-- `system.viewer`) получают идентификатор канонической формы `rol` + 17 знаков
-- алфавита фундамента (задача PRO-Robotech/kaname#543).
--
-- САНКЦИЯ: приёмка docs/engineering/acceptance/system-roles-carry-canonical-ids.md,
-- редакция 3, отпечаток одобренной редакции
-- ab4986a47477a426badfa2dcb0f223218dea4b77d83ab481819dd1ce36ff2130 (записи ревью —
-- docs/specs/reviews/system-roles-carry-canonical-ids/).
--
-- =============================================================================
-- ПОЧЕМУ ПЕРЕНОС, А НЕ ПЕРЕЧЕНЬ ИСКЛЮЧЕНИЙ
-- =============================================================================
-- Свод (`0001_initial.sql`) посеял обе роли рукописными id: у admin в теле буква
-- вне алфавита, у viewer 21 знак. Применённую миграцию править нельзя (ban #5),
-- поэтому id переводит эта миграция. Перевод id ОДНОЙ И ТОЙ ЖЕ роли — не перенос
-- выдачи на другую роль: имя, правила, область и смысл роли те же, а первичный
-- ключ уникален, поэтому каскад слить выдачу с ЧУЖОЙ ролью не может by
-- construction (приёмка §3, Р1).
--
-- =============================================================================
-- ФОРМА: КАСКАД ПО КЛЮЧАМ, ВРЕМЕННО НЕСУЩИМ `ON UPDATE CASCADE`
-- =============================================================================
-- На роль ссылаются 12 внешних ключей, и ни один не несёт `ON UPDATE`. Ключи
-- переводятся на `ON UPDATE CASCADE` на время транзакции, `UPDATE kaname.roles
-- SET id` переносит строку роли и каждую ссылку одним оператором, и ключи
-- возвращаются в прежнее определение ДОСЛОВНО: имя, `ON DELETE`, состав колонок.
-- Остаться навсегда с `ON UPDATE CASCADE` значило бы открыть дорогу будущим тихим
-- переименованиям; равенство схемы до наката и после отката утверждает проба
-- SRCI-10.
--
-- Отвергнуто: вставка копии роли и перевод ссылок выдач оператором
-- `UPDATE kaname.access_bindings SET role_id`. Это написание переноса выдачи между
-- ролями, и гейт `TestNoMigrationMovesGrantsBetweenRoles` его справедливо
-- отвергает: прощать его значило бы ослепить гейт для настоящего переноса.
--
-- Строка роли выбирается ПО ПРЕЖНЕМУ id, а не по имени: имя оператор может
-- сменить. Каждый перевод обязан задеть ровно одну строку, иначе отказ — тихий
-- ноль оставил бы прежний id в силе незаметно ни для кого.
--
-- =============================================================================
-- ЛЕНТА ПОДПИСКИ: ДОПИСЫВАЕТСЯ, НЕ ГЛУШИТСЯ И НЕ ПЕРЕПИСЫВАЕТСЯ (Р4)
-- =============================================================================
-- Подписчик узнаёт о смене id только событиями ленты. Триггеры ленты остаются
-- включёнными: правка строки роли даёт `UPDATED` о НОВОМ id, каскад — `UPDATED` о
-- каждой выдаче на роль. Сверх них подписчику нужно знать, что прежний id снят, а
-- новый появился, — правка `id` этого не говорит. Поэтому миграция дописывает
-- `CREATED` о новом id (ДО правки строки — иначе первым событием о новом id стало
-- бы `UPDATED`) и `DELETED` о прежнем. Строки строятся ТЕМИ ЖЕ функциями, что
-- триггер (`resource_journal_project`, `resource_journal_scope`) над той же
-- строкой роли: своего написания области и якоря здесь нет. Прошлые строки ленты
-- не трогаются: их подписчик уже прочитал.
--
-- =============================================================================
-- ССЫЛКИ БЕЗ КЛЮЧА
-- =============================================================================
-- Каскад не достаёт ссылок, которые ключа не несут. Их три места, и все
-- переписываются здесь: нагрузка очереди аудита (`audit_outbox.event_payload`,
-- поле `role_id` выдачи), оси делегирования (`grant_delegations.role_ids`) и
-- текстовые колонки операций (`operations.description` — «Create access binding
-- (… → <id роли> …)», `error_message`, `resource_id` операций над ролью). Снимки
-- результатов операций (`response_data`, `metadata_data`) — protobuf в `bytea`:
-- перекодировать их SQL нечем, и прежний `roleId` в ответе прошлой операции
-- остаётся (приёмка, вопрос В1 замысла).
-- Места, где id роли мог бы стоять ОБЪЕКТОМ (цель выдачи, факты и журнал
-- отношений, кортежи выдачи), для системной роли недостижимы — роль уровня
-- кластера объектом области не бывает; если строка с прежним id там всё же есть,
-- миграция отказывает, а не оставляет ссылку на снятый id.
--
-- =============================================================================
-- КОНКУРЕНЦИЯ (SRCI-11)
-- =============================================================================
-- Замки всех таблиц, которые переносит каскад, берутся первым оператором в
-- порядке «таблицы-ссылки → роли» — тем же, в каком их берёт вставка выдачи
-- (строка выдачи, затем проверка ключа на роли). Вставка на прежний id либо
-- зафиксирована раньше и переносится каскадом, либо ждёт и после фиксации
-- получает отказ ключа (23503).

-- +goose Up
SET LOCAL lock_timeout = '10s';

LOCK TABLE kaname.access_bindings,
           kaname.access_binding_target_members,
           kaname.role_grant_orphan,
           kaname.role_rule_ref,
           kaname.role_rule_selectors,
           kaname.role_selector_prune,
           kaname.role_selector_verbs_pending,
           kaname.role_verb,
           kaname.roles
    IN ACCESS EXCLUSIVE MODE;

-- Ключи — на время переноса с `ON UPDATE CASCADE`.
ALTER TABLE kaname.access_bindings
    DROP CONSTRAINT access_bindings_role_fk,
    ADD CONSTRAINT access_bindings_role_fk FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON UPDATE CASCADE ON DELETE RESTRICT;
ALTER TABLE kaname.access_binding_target_members
    DROP CONSTRAINT access_binding_target_members_role_fk,
    DROP CONSTRAINT access_binding_target_members_role_live_fk,
    ADD CONSTRAINT access_binding_target_members_role_fk FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON UPDATE CASCADE ON DELETE CASCADE,
    ADD CONSTRAINT access_binding_target_members_role_live_fk FOREIGN KEY (role_id, live)
        REFERENCES kaname.roles(id, live) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE kaname.role_grant_orphan
    DROP CONSTRAINT role_grant_orphan_role_id_fkey,
    ADD CONSTRAINT role_grant_orphan_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE kaname.role_rule_ref
    DROP CONSTRAINT role_rule_ref_role_id_fkey,
    DROP CONSTRAINT role_rule_ref_role_live_fk,
    ADD CONSTRAINT role_rule_ref_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON UPDATE CASCADE ON DELETE CASCADE,
    ADD CONSTRAINT role_rule_ref_role_live_fk FOREIGN KEY (role_id, live)
        REFERENCES kaname.roles(id, live) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE kaname.role_rule_selectors
    DROP CONSTRAINT role_rule_selectors_role_id_fkey,
    DROP CONSTRAINT role_rule_selectors_role_live_fk,
    ADD CONSTRAINT role_rule_selectors_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON UPDATE CASCADE ON DELETE CASCADE,
    ADD CONSTRAINT role_rule_selectors_role_live_fk FOREIGN KEY (role_id, live)
        REFERENCES kaname.roles(id, live) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE kaname.role_selector_prune
    DROP CONSTRAINT role_selector_prune_role_id_fkey,
    ADD CONSTRAINT role_selector_prune_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE kaname.role_selector_verbs_pending
    DROP CONSTRAINT role_selector_verbs_pending_role_id_fkey,
    ADD CONSTRAINT role_selector_verbs_pending_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE kaname.role_verb
    DROP CONSTRAINT role_verb_role_id_fkey,
    DROP CONSTRAINT role_verb_role_live_fk,
    ADD CONSTRAINT role_verb_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON UPDATE CASCADE ON DELETE CASCADE,
    ADD CONSTRAINT role_verb_role_live_fk FOREIGN KEY (role_id, live)
        REFERENCES kaname.roles(id, live) ON UPDATE CASCADE ON DELETE CASCADE;

-- +goose StatementBegin
DO $$
DECLARE
    v_row  jsonb;
    v_rows bigint;
BEGIN
    IF EXISTS (SELECT 1 FROM kaname.roles WHERE id IN ('rol58ksy03r9xd053my3', 'rol6ht762gm6sj2cdvan')) THEN
        RAISE EXCEPTION 'новый id системной роли уже занят строкой kaname.roles: перенос на занятый id слил бы две роли.';
    END IF;

    -- system.admin
    SELECT to_jsonb(r) INTO v_row FROM kaname.roles r WHERE r.id = 'rol000000000sysadmin' AND r.is_system;
    IF v_row IS NULL THEN
        RAISE EXCEPTION 'системной роли с прежним id admin в таблице нет: её сеет свод, и молчаливый проход выдал бы непереведённую роль за переведённую.';
    END IF;
    INSERT INTO kaname.resource_journal (resource_kind, resource_id, project_id, scope, event_type, payload)
    VALUES ('iam_role', 'rol58ksy03r9xd053my3',
            kaname.resource_journal_project('iam_role', v_row || jsonb_build_object('id', 'rol58ksy03r9xd053my3')),
            kaname.resource_journal_scope('iam_role', v_row || jsonb_build_object('id', 'rol58ksy03r9xd053my3')),
            'CREATED', jsonb_build_object('id', 'rol58ksy03r9xd053my3'));
    UPDATE kaname.roles SET id = 'rol58ksy03r9xd053my3' WHERE id = 'rol000000000sysadmin';
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows <> 1 THEN
        RAISE EXCEPTION 'перевод id роли system.admin задел строк %, ожидалась одна.', v_rows;
    END IF;
    INSERT INTO kaname.resource_journal (resource_kind, resource_id, project_id, scope, event_type, payload)
    VALUES ('iam_role', 'rol000000000sysadmin',
            kaname.resource_journal_project('iam_role', v_row),
            kaname.resource_journal_scope('iam_role', v_row),
            'DELETED', jsonb_build_object('id', 'rol000000000sysadmin'));

    -- system.viewer
    SELECT to_jsonb(r) INTO v_row FROM kaname.roles r WHERE r.id = 'rol000000000sysviewer' AND r.is_system;
    IF v_row IS NULL THEN
        RAISE EXCEPTION 'системной роли с прежним id viewer в таблице нет: её сеет свод, и молчаливый проход выдал бы непереведённую роль за переведённую.';
    END IF;
    INSERT INTO kaname.resource_journal (resource_kind, resource_id, project_id, scope, event_type, payload)
    VALUES ('iam_role', 'rol6ht762gm6sj2cdvan',
            kaname.resource_journal_project('iam_role', v_row || jsonb_build_object('id', 'rol6ht762gm6sj2cdvan')),
            kaname.resource_journal_scope('iam_role', v_row || jsonb_build_object('id', 'rol6ht762gm6sj2cdvan')),
            'CREATED', jsonb_build_object('id', 'rol6ht762gm6sj2cdvan'));
    UPDATE kaname.roles SET id = 'rol6ht762gm6sj2cdvan' WHERE id = 'rol000000000sysviewer';
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows <> 1 THEN
        RAISE EXCEPTION 'перевод id роли system.viewer задел строк %, ожидалась одна.', v_rows;
    END IF;
    INSERT INTO kaname.resource_journal (resource_kind, resource_id, project_id, scope, event_type, payload)
    VALUES ('iam_role', 'rol000000000sysviewer',
            kaname.resource_journal_project('iam_role', v_row),
            kaname.resource_journal_scope('iam_role', v_row),
            'DELETED', jsonb_build_object('id', 'rol000000000sysviewer'));

    -- Ссылки без ключа.
    UPDATE kaname.audit_outbox
       SET event_payload = replace(replace(event_payload::text,
               'rol000000000sysadmin', 'rol58ksy03r9xd053my3'),
               'rol000000000sysviewer', 'rol6ht762gm6sj2cdvan')::jsonb
     WHERE strpos(event_payload::text, 'rol000000000sysadmin') > 0
        OR strpos(event_payload::text, 'rol000000000sysviewer') > 0;
    UPDATE kaname.grant_delegations
       SET role_ids = array_replace(array_replace(role_ids,
               'rol000000000sysadmin', 'rol58ksy03r9xd053my3'),
               'rol000000000sysviewer', 'rol6ht762gm6sj2cdvan')
     WHERE role_ids && ARRAY['rol000000000sysadmin', 'rol000000000sysviewer'];
    UPDATE kaname.operations
       SET description = replace(replace(description,
               'rol000000000sysadmin', 'rol58ksy03r9xd053my3'),
               'rol000000000sysviewer', 'rol6ht762gm6sj2cdvan'),
           error_message = replace(replace(error_message,
               'rol000000000sysadmin', 'rol58ksy03r9xd053my3'),
               'rol000000000sysviewer', 'rol6ht762gm6sj2cdvan'),
           resource_id = CASE resource_id
               WHEN 'rol000000000sysadmin' THEN 'rol58ksy03r9xd053my3'
               WHEN 'rol000000000sysviewer' THEN 'rol6ht762gm6sj2cdvan'
               ELSE resource_id END
     WHERE strpos(description, 'rol000000000sysadmin') > 0
        OR strpos(description, 'rol000000000sysviewer') > 0
        OR strpos(COALESCE(error_message, ''), 'rol000000000sysadmin') > 0
        OR strpos(COALESCE(error_message, ''), 'rol000000000sysviewer') > 0
        OR resource_id IN ('rol000000000sysadmin', 'rol000000000sysviewer');

    -- Объектом системная роль не бывает; строка, говорящая обратное, — отказ.
    IF EXISTS (SELECT 1 FROM kaname.access_bindings t
                WHERE strpos(t.target::text, 'rol000000000sysadmin') > 0
                   OR strpos(t.target::text, 'rol000000000sysviewer') > 0)
       OR EXISTS (SELECT 1 FROM kaname.relation_fact t
                   WHERE strpos(t::text, 'rol000000000sysadmin') > 0
                      OR strpos(t::text, 'rol000000000sysviewer') > 0)
       OR EXISTS (SELECT 1 FROM kaname.fga_outbox t
                   WHERE strpos(t::text, 'rol000000000sysadmin') > 0
                      OR strpos(t::text, 'rol000000000sysviewer') > 0)
       OR EXISTS (SELECT 1 FROM kaname.access_binding_emitted_tuples t
                   WHERE strpos(t::text, 'rol000000000sysadmin') > 0
                      OR strpos(t::text, 'rol000000000sysviewer') > 0) THEN
        RAISE EXCEPTION 'прежний id системной роли стоит объектом в цели выдачи либо в отношениях: такой ссылки миграция не переносит, а оставить её значило бы указывать на снятый id.';
    END IF;
END $$;
-- +goose StatementEnd

-- Ключи — в прежнее определение дословно.
ALTER TABLE kaname.access_bindings
    DROP CONSTRAINT access_bindings_role_fk,
    ADD CONSTRAINT access_bindings_role_fk FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON DELETE RESTRICT;
ALTER TABLE kaname.access_binding_target_members
    DROP CONSTRAINT access_binding_target_members_role_fk,
    DROP CONSTRAINT access_binding_target_members_role_live_fk,
    ADD CONSTRAINT access_binding_target_members_role_fk FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON DELETE CASCADE,
    ADD CONSTRAINT access_binding_target_members_role_live_fk FOREIGN KEY (role_id, live)
        REFERENCES kaname.roles(id, live) ON DELETE CASCADE;
ALTER TABLE kaname.role_grant_orphan
    DROP CONSTRAINT role_grant_orphan_role_id_fkey,
    ADD CONSTRAINT role_grant_orphan_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON DELETE CASCADE;
ALTER TABLE kaname.role_rule_ref
    DROP CONSTRAINT role_rule_ref_role_id_fkey,
    DROP CONSTRAINT role_rule_ref_role_live_fk,
    ADD CONSTRAINT role_rule_ref_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON DELETE CASCADE,
    ADD CONSTRAINT role_rule_ref_role_live_fk FOREIGN KEY (role_id, live)
        REFERENCES kaname.roles(id, live) ON DELETE CASCADE;
ALTER TABLE kaname.role_rule_selectors
    DROP CONSTRAINT role_rule_selectors_role_id_fkey,
    DROP CONSTRAINT role_rule_selectors_role_live_fk,
    ADD CONSTRAINT role_rule_selectors_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON DELETE CASCADE,
    ADD CONSTRAINT role_rule_selectors_role_live_fk FOREIGN KEY (role_id, live)
        REFERENCES kaname.roles(id, live) ON DELETE CASCADE;
ALTER TABLE kaname.role_selector_prune
    DROP CONSTRAINT role_selector_prune_role_id_fkey,
    ADD CONSTRAINT role_selector_prune_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON DELETE CASCADE;
ALTER TABLE kaname.role_selector_verbs_pending
    DROP CONSTRAINT role_selector_verbs_pending_role_id_fkey,
    ADD CONSTRAINT role_selector_verbs_pending_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON DELETE CASCADE;
ALTER TABLE kaname.role_verb
    DROP CONSTRAINT role_verb_role_id_fkey,
    DROP CONSTRAINT role_verb_role_live_fk,
    ADD CONSTRAINT role_verb_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON DELETE CASCADE,
    ADD CONSTRAINT role_verb_role_live_fk FOREIGN KEY (role_id, live)
        REFERENCES kaname.roles(id, live) ON DELETE CASCADE;

-- +goose Down
--
-- Обратный ход зеркален: `CREATED` о прежнем id до правки строки, правка строки
-- каскадом, `DELETED` о новом id; ссылки без ключа — обратно. Строки ленты,
-- дописанные накатом, остаются: лента только дописывается (Р4). Выдача, сделанная
-- на новый id между накатом и откатом, каскадом уходит на прежний id и не
-- теряется (SRCI-10б).
SET LOCAL lock_timeout = '10s';

LOCK TABLE kaname.access_bindings,
           kaname.access_binding_target_members,
           kaname.role_grant_orphan,
           kaname.role_rule_ref,
           kaname.role_rule_selectors,
           kaname.role_selector_prune,
           kaname.role_selector_verbs_pending,
           kaname.role_verb,
           kaname.roles
    IN ACCESS EXCLUSIVE MODE;

ALTER TABLE kaname.access_bindings
    DROP CONSTRAINT access_bindings_role_fk,
    ADD CONSTRAINT access_bindings_role_fk FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON UPDATE CASCADE ON DELETE RESTRICT;
ALTER TABLE kaname.access_binding_target_members
    DROP CONSTRAINT access_binding_target_members_role_fk,
    DROP CONSTRAINT access_binding_target_members_role_live_fk,
    ADD CONSTRAINT access_binding_target_members_role_fk FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON UPDATE CASCADE ON DELETE CASCADE,
    ADD CONSTRAINT access_binding_target_members_role_live_fk FOREIGN KEY (role_id, live)
        REFERENCES kaname.roles(id, live) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE kaname.role_grant_orphan
    DROP CONSTRAINT role_grant_orphan_role_id_fkey,
    ADD CONSTRAINT role_grant_orphan_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE kaname.role_rule_ref
    DROP CONSTRAINT role_rule_ref_role_id_fkey,
    DROP CONSTRAINT role_rule_ref_role_live_fk,
    ADD CONSTRAINT role_rule_ref_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON UPDATE CASCADE ON DELETE CASCADE,
    ADD CONSTRAINT role_rule_ref_role_live_fk FOREIGN KEY (role_id, live)
        REFERENCES kaname.roles(id, live) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE kaname.role_rule_selectors
    DROP CONSTRAINT role_rule_selectors_role_id_fkey,
    DROP CONSTRAINT role_rule_selectors_role_live_fk,
    ADD CONSTRAINT role_rule_selectors_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON UPDATE CASCADE ON DELETE CASCADE,
    ADD CONSTRAINT role_rule_selectors_role_live_fk FOREIGN KEY (role_id, live)
        REFERENCES kaname.roles(id, live) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE kaname.role_selector_prune
    DROP CONSTRAINT role_selector_prune_role_id_fkey,
    ADD CONSTRAINT role_selector_prune_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE kaname.role_selector_verbs_pending
    DROP CONSTRAINT role_selector_verbs_pending_role_id_fkey,
    ADD CONSTRAINT role_selector_verbs_pending_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE kaname.role_verb
    DROP CONSTRAINT role_verb_role_id_fkey,
    DROP CONSTRAINT role_verb_role_live_fk,
    ADD CONSTRAINT role_verb_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON UPDATE CASCADE ON DELETE CASCADE,
    ADD CONSTRAINT role_verb_role_live_fk FOREIGN KEY (role_id, live)
        REFERENCES kaname.roles(id, live) ON UPDATE CASCADE ON DELETE CASCADE;

-- +goose StatementBegin
DO $$
DECLARE
    v_row  jsonb;
    v_rows bigint;
BEGIN
    IF EXISTS (SELECT 1 FROM kaname.roles WHERE id IN ('rol000000000sysadmin', 'rol000000000sysviewer')) THEN
        RAISE EXCEPTION 'прежний id системной роли уже занят строкой kaname.roles: обратный перенос слил бы две роли.';
    END IF;

    -- system.admin
    SELECT to_jsonb(r) INTO v_row FROM kaname.roles r WHERE r.id = 'rol58ksy03r9xd053my3' AND r.is_system;
    IF v_row IS NULL THEN
        RAISE EXCEPTION 'системной роли с новым id admin в таблице нет: откатывать нечего, и молчаливый проход выдал бы это за откат.';
    END IF;
    INSERT INTO kaname.resource_journal (resource_kind, resource_id, project_id, scope, event_type, payload)
    VALUES ('iam_role', 'rol000000000sysadmin',
            kaname.resource_journal_project('iam_role', v_row || jsonb_build_object('id', 'rol000000000sysadmin')),
            kaname.resource_journal_scope('iam_role', v_row || jsonb_build_object('id', 'rol000000000sysadmin')),
            'CREATED', jsonb_build_object('id', 'rol000000000sysadmin'));
    UPDATE kaname.roles SET id = 'rol000000000sysadmin' WHERE id = 'rol58ksy03r9xd053my3';
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows <> 1 THEN
        RAISE EXCEPTION 'обратный перевод id роли system.admin задел строк %, ожидалась одна.', v_rows;
    END IF;
    INSERT INTO kaname.resource_journal (resource_kind, resource_id, project_id, scope, event_type, payload)
    VALUES ('iam_role', 'rol58ksy03r9xd053my3',
            kaname.resource_journal_project('iam_role', v_row),
            kaname.resource_journal_scope('iam_role', v_row),
            'DELETED', jsonb_build_object('id', 'rol58ksy03r9xd053my3'));

    -- system.viewer
    SELECT to_jsonb(r) INTO v_row FROM kaname.roles r WHERE r.id = 'rol6ht762gm6sj2cdvan' AND r.is_system;
    IF v_row IS NULL THEN
        RAISE EXCEPTION 'системной роли с новым id viewer в таблице нет: откатывать нечего, и молчаливый проход выдал бы это за откат.';
    END IF;
    INSERT INTO kaname.resource_journal (resource_kind, resource_id, project_id, scope, event_type, payload)
    VALUES ('iam_role', 'rol000000000sysviewer',
            kaname.resource_journal_project('iam_role', v_row || jsonb_build_object('id', 'rol000000000sysviewer')),
            kaname.resource_journal_scope('iam_role', v_row || jsonb_build_object('id', 'rol000000000sysviewer')),
            'CREATED', jsonb_build_object('id', 'rol000000000sysviewer'));
    UPDATE kaname.roles SET id = 'rol000000000sysviewer' WHERE id = 'rol6ht762gm6sj2cdvan';
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows <> 1 THEN
        RAISE EXCEPTION 'обратный перевод id роли system.viewer задел строк %, ожидалась одна.', v_rows;
    END IF;
    INSERT INTO kaname.resource_journal (resource_kind, resource_id, project_id, scope, event_type, payload)
    VALUES ('iam_role', 'rol6ht762gm6sj2cdvan',
            kaname.resource_journal_project('iam_role', v_row),
            kaname.resource_journal_scope('iam_role', v_row),
            'DELETED', jsonb_build_object('id', 'rol6ht762gm6sj2cdvan'));

    UPDATE kaname.audit_outbox
       SET event_payload = replace(replace(event_payload::text,
               'rol58ksy03r9xd053my3', 'rol000000000sysadmin'),
               'rol6ht762gm6sj2cdvan', 'rol000000000sysviewer')::jsonb
     WHERE strpos(event_payload::text, 'rol58ksy03r9xd053my3') > 0
        OR strpos(event_payload::text, 'rol6ht762gm6sj2cdvan') > 0;
    UPDATE kaname.grant_delegations
       SET role_ids = array_replace(array_replace(role_ids,
               'rol58ksy03r9xd053my3', 'rol000000000sysadmin'),
               'rol6ht762gm6sj2cdvan', 'rol000000000sysviewer')
     WHERE role_ids && ARRAY['rol58ksy03r9xd053my3', 'rol6ht762gm6sj2cdvan'];
    UPDATE kaname.operations
       SET description = replace(replace(description,
               'rol58ksy03r9xd053my3', 'rol000000000sysadmin'),
               'rol6ht762gm6sj2cdvan', 'rol000000000sysviewer'),
           error_message = replace(replace(error_message,
               'rol58ksy03r9xd053my3', 'rol000000000sysadmin'),
               'rol6ht762gm6sj2cdvan', 'rol000000000sysviewer'),
           resource_id = CASE resource_id
               WHEN 'rol58ksy03r9xd053my3' THEN 'rol000000000sysadmin'
               WHEN 'rol6ht762gm6sj2cdvan' THEN 'rol000000000sysviewer'
               ELSE resource_id END
     WHERE strpos(description, 'rol58ksy03r9xd053my3') > 0
        OR strpos(description, 'rol6ht762gm6sj2cdvan') > 0
        OR strpos(COALESCE(error_message, ''), 'rol58ksy03r9xd053my3') > 0
        OR strpos(COALESCE(error_message, ''), 'rol6ht762gm6sj2cdvan') > 0
        OR resource_id IN ('rol58ksy03r9xd053my3', 'rol6ht762gm6sj2cdvan');

    IF EXISTS (SELECT 1 FROM kaname.access_bindings t
                WHERE strpos(t.target::text, 'rol58ksy03r9xd053my3') > 0
                   OR strpos(t.target::text, 'rol6ht762gm6sj2cdvan') > 0)
       OR EXISTS (SELECT 1 FROM kaname.relation_fact t
                   WHERE strpos(t::text, 'rol58ksy03r9xd053my3') > 0
                      OR strpos(t::text, 'rol6ht762gm6sj2cdvan') > 0)
       OR EXISTS (SELECT 1 FROM kaname.fga_outbox t
                   WHERE strpos(t::text, 'rol58ksy03r9xd053my3') > 0
                      OR strpos(t::text, 'rol6ht762gm6sj2cdvan') > 0)
       OR EXISTS (SELECT 1 FROM kaname.access_binding_emitted_tuples t
                   WHERE strpos(t::text, 'rol58ksy03r9xd053my3') > 0
                      OR strpos(t::text, 'rol6ht762gm6sj2cdvan') > 0) THEN
        RAISE EXCEPTION 'новый id системной роли стоит объектом в цели выдачи либо в отношениях: такой ссылки откат не переносит, а оставить её значило бы указывать на снятый id.';
    END IF;
END $$;
-- +goose StatementEnd

ALTER TABLE kaname.access_bindings
    DROP CONSTRAINT access_bindings_role_fk,
    ADD CONSTRAINT access_bindings_role_fk FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON DELETE RESTRICT;
ALTER TABLE kaname.access_binding_target_members
    DROP CONSTRAINT access_binding_target_members_role_fk,
    DROP CONSTRAINT access_binding_target_members_role_live_fk,
    ADD CONSTRAINT access_binding_target_members_role_fk FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON DELETE CASCADE,
    ADD CONSTRAINT access_binding_target_members_role_live_fk FOREIGN KEY (role_id, live)
        REFERENCES kaname.roles(id, live) ON DELETE CASCADE;
ALTER TABLE kaname.role_grant_orphan
    DROP CONSTRAINT role_grant_orphan_role_id_fkey,
    ADD CONSTRAINT role_grant_orphan_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON DELETE CASCADE;
ALTER TABLE kaname.role_rule_ref
    DROP CONSTRAINT role_rule_ref_role_id_fkey,
    DROP CONSTRAINT role_rule_ref_role_live_fk,
    ADD CONSTRAINT role_rule_ref_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON DELETE CASCADE,
    ADD CONSTRAINT role_rule_ref_role_live_fk FOREIGN KEY (role_id, live)
        REFERENCES kaname.roles(id, live) ON DELETE CASCADE;
ALTER TABLE kaname.role_rule_selectors
    DROP CONSTRAINT role_rule_selectors_role_id_fkey,
    DROP CONSTRAINT role_rule_selectors_role_live_fk,
    ADD CONSTRAINT role_rule_selectors_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON DELETE CASCADE,
    ADD CONSTRAINT role_rule_selectors_role_live_fk FOREIGN KEY (role_id, live)
        REFERENCES kaname.roles(id, live) ON DELETE CASCADE;
ALTER TABLE kaname.role_selector_prune
    DROP CONSTRAINT role_selector_prune_role_id_fkey,
    ADD CONSTRAINT role_selector_prune_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON DELETE CASCADE;
ALTER TABLE kaname.role_selector_verbs_pending
    DROP CONSTRAINT role_selector_verbs_pending_role_id_fkey,
    ADD CONSTRAINT role_selector_verbs_pending_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON DELETE CASCADE;
ALTER TABLE kaname.role_verb
    DROP CONSTRAINT role_verb_role_id_fkey,
    DROP CONSTRAINT role_verb_role_live_fk,
    ADD CONSTRAINT role_verb_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES kaname.roles(id) ON DELETE CASCADE,
    ADD CONSTRAINT role_verb_role_live_fk FOREIGN KEY (role_id, live)
        REFERENCES kaname.roles(id, live) ON DELETE CASCADE;
