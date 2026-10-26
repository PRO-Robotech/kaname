-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- service_account_creation_is_its_own_right — создание служебных учёток как
-- отдельное право (задача PRO-Robotech/kaname#1003).
--
-- САНКЦИЯ: приёмка docs/engineering/acceptance/service-account-creation-is-its-own-right.md,
-- редакция 3, отпечаток одобренной редакции
-- cd31c47cb19dea4163a70a4e181545c2462e0ef0a62d5f330a23f66fe14bc08f (записи ревью —
-- docs/specs/reviews/service-account-creation-is-its-own-right/).
--
-- ЧТО МЕНЯЕТСЯ:
--
--   1. `kaname.catalog_verb.container_parent` / `container_relation` — строка
--      каталога есть КОНТЕЙНЕРНОЕ действие (Р2а): действие над ресурсом, которое
--      авторизуется отношением на родителе. Пишет их применитель каталога из
--      `containerVerbs` манифеста модуля. Схема держит пару: обе колонки заданы
--      либо обе пусты; контейнерная строка ярусная (`per_object = false` — в набор
--      глаголов типа не входит, подстановка её не достигает); отношение без
--      приставки `v_`. Посев: у манифеста iam ровно одно контейнерное действие —
--      `create` у `serviceAccount` → `account#service_account_creator`; его строка
--      уже посеяна ярусной (`create`, `per_object = false`) и получает пару.
--   2. `kaname.service_accounts.created_by_type` / `created_by_id` — ФАКТ СОЗДАТЕЛЯ
--      (Р4): принципал, вызвавший `ServiceAccountService.Create`, пишется в той же
--      транзакции, что строка учётки. Пара задана либо пуста целиком (учётки до
--      изменения — без создателя, обратного заполнения нет: §2 п.4); вид — `user`
--      или `service_account`. Факт НЕИЗМЕНЯЕМ: правку держит триггер, а не код
--      (ban #10), — ведение по роли создателя есть функция этого факта, и правка
--      передала бы чужие учётки другому создателю. Снимается вместе со строкой
--      учётки; учётка-создатель может быть удалена раньше — её id в факте остаётся
--      и никого не ведёт (id не переиспользуется). Индекс по (аккаунт, создатель) —
--      отбор учёток создателя на аккаунте без перебора учёток аккаунта (§3,
--      «производительность»; DoD S1 п.8).
--   3. `kaname.role_rule_selectors.created_by_subject` — селектор СОЗДАТЕЛЯ правила
--      роли (Р2а): решение о доступе даёт глагол такого правила только на объекте,
--      создатель которого — субъект выдачи. Строка с селектором — ветвь якоря
--      верхнего уровня (селекторы у правила взаимоисключающи, вложенного правила с
--      селектором нет).
--   4. `kaname.iam_rules_valid` — хранимая форма правила роли несёт ключ
--      `created_by_subject` только значением true, без `resource_names`,
--      `match_labels`, `children` и без подстановки в модуле и ресурсе.
--   Системную роль `iam.service_account.creator` (Р2) эта миграция НЕ заводит: роль
--   модуля с манифестом объявляется манифестом, и строку пишет применитель ролей
--   на старте (`moduleroles.Applier.ApplyImage` над манифестом образа) —
--   `TestMODRD23MigrationDoesNotWriteARoleOfAManifestBearingModule`.

-- +goose Up

-- 1. Контейнерное действие в каталоге.
ALTER TABLE kaname.catalog_verb
    ADD COLUMN container_parent text,
    ADD COLUMN container_relation text,
    ADD CONSTRAINT catalog_verb_container_pair_ck
        CHECK ((container_parent IS NULL) = (container_relation IS NULL)),
    ADD CONSTRAINT catalog_verb_container_is_tier_ck
        CHECK (container_relation IS NULL OR NOT per_object),
    ADD CONSTRAINT catalog_verb_container_relation_form_ck
        CHECK (container_relation IS NULL OR (container_relation ~ '^[a-z][a-z0-9_]*$' AND container_relation !~ '^v_'));

COMMENT ON COLUMN kaname.catalog_verb.container_relation IS
    'Контейнерное действие (kaname#1003, Р2а): отношение на родителе типа container_parent, которое даёт поимённо названное действие. NULL — действие не контейнерное.';

UPDATE kaname.catalog_verb
   SET container_parent = 'account', container_relation = 'service_account_creator'
 WHERE module = 'iam' AND resource = 'serviceAccount' AND verb = 'create' AND live;

-- 2. Факт создателя учётки.
ALTER TABLE kaname.service_accounts
    ADD COLUMN created_by_type text,
    ADD COLUMN created_by_id text,
    ADD CONSTRAINT service_accounts_creator_pair_ck
        CHECK ((created_by_type IS NULL) = (created_by_id IS NULL)),
    ADD CONSTRAINT service_accounts_creator_type_ck
        CHECK (created_by_type IS NULL OR created_by_type IN ('user', 'service_account')),
    ADD CONSTRAINT service_accounts_creator_id_nonempty_ck
        CHECK (created_by_id IS NULL OR created_by_id <> '');

COMMENT ON COLUMN kaname.service_accounts.created_by_id IS
    'Факт создателя (kaname#1003, Р4): принципал, вызвавший ServiceAccountService.Create. Неизменяем (service_account_creator_is_immutable); наружу не выдаётся.';

CREATE INDEX service_accounts_creator_idx
    ON kaname.service_accounts (account_id, created_by_id)
 WHERE created_by_type = 'service_account';

-- +goose StatementBegin
CREATE FUNCTION kaname.service_account_creator_is_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.created_by_type IS DISTINCT FROM OLD.created_by_type
       OR NEW.created_by_id IS DISTINCT FROM OLD.created_by_id THEN
        RAISE EXCEPTION 'service account % creator is immutable', OLD.id
            USING ERRCODE = '23514', CONSTRAINT = 'service_accounts_creator_immutable';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER service_account_creator_is_immutable
    BEFORE UPDATE OF created_by_type, created_by_id ON kaname.service_accounts
    FOR EACH ROW EXECUTE FUNCTION kaname.service_account_creator_is_immutable();

-- 3. Селектор создателя у строки селектора правила роли.
ALTER TABLE kaname.role_rule_selectors
    ADD COLUMN created_by_subject boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT role_rule_selectors_creator_is_top_anchor_ck
        CHECK (NOT created_by_subject OR (arm = 'anchor' AND container_type IS NULL));

COMMENT ON COLUMN kaname.role_rule_selectors.created_by_subject IS
    'Селектор создателя (kaname#1003, Р2а): глагол правила действует только на объекте, создатель которого — субъект выдачи.';

-- 4. Хранимая форма правила роли.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.iam_rules_valid(rules jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
DECLARE
    rule       jsonb;
    child      jsonb;
    arr        jsonb;
    has_names  boolean;
    has_labels boolean;
BEGIN
    IF rules IS NULL THEN RETURN false; END IF;
    IF jsonb_typeof(rules) <> 'array' THEN RETURN false; END IF;
    -- Empty array is valid (legacy permissions-only role; back-compat).
    IF jsonb_array_length(rules) = 0 THEN RETURN true; END IF;
    IF jsonb_array_length(rules) > 64 THEN RETURN false; END IF;

    FOR rule IN SELECT value FROM jsonb_array_elements(rules) LOOP
        IF jsonb_typeof(rule) <> 'object' THEN RETURN false; END IF;

        -- module: required, non-empty string scalar. The array `modules` key is
        -- NO LONGER valid.
        IF NOT (rule ? 'module') THEN RETURN false; END IF;
        IF jsonb_typeof(rule -> 'module') <> 'string' THEN RETURN false; END IF;
        IF length(rule ->> 'module') < 1 THEN RETURN false; END IF;

        -- resources / verbs: required non-empty string arrays, 1..16.
        FOR arr IN SELECT rule -> k FROM (VALUES ('resources'), ('verbs')) AS t(k) LOOP
            IF arr IS NULL OR jsonb_typeof(arr) <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(arr) < 1 OR jsonb_array_length(arr) > 16 THEN RETURN false; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements(arr) e WHERE jsonb_typeof(e) <> 'string') THEN
                RETURN false;
            END IF;
        END LOOP;

        has_names  := (rule ? 'resource_names') AND jsonb_typeof(rule -> 'resource_names') <> 'null';
        has_labels := (rule ? 'match_labels')   AND jsonb_typeof(rule -> 'match_labels')   <> 'null';

        -- resource_names XOR match_labels (both → reject).
        IF has_names AND has_labels THEN RETURN false; END IF;

        IF has_names THEN
            IF jsonb_typeof(rule -> 'resource_names') <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'resource_names') > 256 THEN RETURN false; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements(rule -> 'resource_names') e
                       WHERE jsonb_typeof(e) <> 'string') THEN
                RETURN false;
            END IF;
        END IF;

        IF has_labels THEN
            IF jsonb_typeof(rule -> 'match_labels') <> 'object' THEN RETURN false; END IF;
            IF (SELECT count(*) FROM jsonb_object_keys(rule -> 'match_labels')) NOT BETWEEN 1 AND 16 THEN
                RETURN false;
            END IF;
        END IF;

        -- Селектор создателя (kaname#1003, Р2а). Ключа нет — селектора нет; ключ
        -- пишется только значением true (второго способа сказать «нет» хранимая
        -- форма не несёт). Селектор у правила один: не с resource_names и не с
        -- match_labels. Вид объекта назван поимённо: ни модуль, ни ресурс не
        -- подстановка. Вложенных правил у правила с селектором нет.
        IF rule ? 'created_by_subject' THEN
            IF jsonb_typeof(rule -> 'created_by_subject') <> 'boolean' THEN RETURN false; END IF;
            IF NOT (rule -> 'created_by_subject')::boolean THEN RETURN false; END IF;
            IF has_names OR has_labels THEN RETURN false; END IF;
            IF rule ->> 'module' = '*' THEN RETURN false; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements_text(rule -> 'resources') e WHERE e = '*') THEN
                RETURN false;
            END IF;
            IF rule ? 'children' THEN RETURN false; END IF;
        END IF;

        -- Вложенные правила (kaname#874). Ключа нет — правило без вложенных.
        IF rule ? 'children' THEN
            IF jsonb_typeof(rule -> 'children') <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'children') NOT BETWEEN 1 AND 16 THEN RETURN false; END IF;
            -- Владелец — ровно один ресурс, не подстановка, модуль не подстановка.
            IF rule ->> 'module' = '*' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'resources') <> 1 THEN RETURN false; END IF;
            IF rule -> 'resources' ->> 0 = '*' THEN RETURN false; END IF;

            FOR child IN SELECT value FROM jsonb_array_elements(rule -> 'children') LOOP
                IF jsonb_typeof(child) <> 'object' THEN RETURN false; END IF;
                -- Модуль — владельца; глубину выражает тип, а не структура роли.
                IF child ? 'module' OR child ? 'children' THEN RETURN false; END IF;
                FOR arr IN SELECT child -> k FROM (VALUES ('resources'), ('verbs')) AS t(k) LOOP
                    IF arr IS NULL OR jsonb_typeof(arr) <> 'array' THEN RETURN false; END IF;
                    IF jsonb_array_length(arr) < 1 OR jsonb_array_length(arr) > 16 THEN RETURN false; END IF;
                    IF EXISTS (SELECT 1 FROM jsonb_array_elements(arr) e WHERE jsonb_typeof(e) <> 'string') THEN
                        RETURN false;
                    END IF;
                END LOOP;
                -- Вложенное называет тип: не подстановку и не тип владельца.
                IF EXISTS (SELECT 1 FROM jsonb_array_elements_text(child -> 'resources') e
                            WHERE e = '*' OR e = rule -> 'resources' ->> 0) THEN
                    RETURN false;
                END IF;

                has_names  := (child ? 'resource_names') AND jsonb_typeof(child -> 'resource_names') <> 'null';
                has_labels := (child ? 'match_labels')   AND jsonb_typeof(child -> 'match_labels')   <> 'null';
                IF has_names AND has_labels THEN RETURN false; END IF;
                IF has_names THEN
                    IF jsonb_typeof(child -> 'resource_names') <> 'array' THEN RETURN false; END IF;
                    IF jsonb_array_length(child -> 'resource_names') > 256 THEN RETURN false; END IF;
                    IF EXISTS (SELECT 1 FROM jsonb_array_elements(child -> 'resource_names') e
                               WHERE jsonb_typeof(e) <> 'string') THEN
                        RETURN false;
                    END IF;
                END IF;
                IF has_labels THEN
                    IF jsonb_typeof(child -> 'match_labels') <> 'object' THEN RETURN false; END IF;
                    IF (SELECT count(*) FROM jsonb_object_keys(child -> 'match_labels')) NOT BETWEEN 1 AND 16 THEN
                        RETURN false;
                    END IF;
                END IF;
            END LOOP;
        END IF;
    END LOOP;

    RETURN true;
END;
$$;
-- +goose StatementEnd


-- +goose Down

-- Роль создателя заводит применитель ролей, но её правило с селектором создателя
-- без колонки селектора читалось бы «глаголы на всех учётках»: откат схемы снимает
-- строку роли (выдачи на неё откат останавливают ключом — громко, а не молча).
DELETE FROM kaname.roles WHERE name = 'iam.service_account.creator';

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.iam_rules_valid(rules jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
DECLARE
    rule       jsonb;
    child      jsonb;
    arr        jsonb;
    has_names  boolean;
    has_labels boolean;
BEGIN
    IF rules IS NULL THEN RETURN false; END IF;
    IF jsonb_typeof(rules) <> 'array' THEN RETURN false; END IF;
    -- Empty array is valid (legacy permissions-only role; back-compat).
    IF jsonb_array_length(rules) = 0 THEN RETURN true; END IF;
    IF jsonb_array_length(rules) > 64 THEN RETURN false; END IF;

    FOR rule IN SELECT value FROM jsonb_array_elements(rules) LOOP
        IF jsonb_typeof(rule) <> 'object' THEN RETURN false; END IF;

        -- module: required, non-empty string scalar. The array `modules` key is
        -- NO LONGER valid.
        IF NOT (rule ? 'module') THEN RETURN false; END IF;
        IF jsonb_typeof(rule -> 'module') <> 'string' THEN RETURN false; END IF;
        IF length(rule ->> 'module') < 1 THEN RETURN false; END IF;

        -- resources / verbs: required non-empty string arrays, 1..16.
        FOR arr IN SELECT rule -> k FROM (VALUES ('resources'), ('verbs')) AS t(k) LOOP
            IF arr IS NULL OR jsonb_typeof(arr) <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(arr) < 1 OR jsonb_array_length(arr) > 16 THEN RETURN false; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements(arr) e WHERE jsonb_typeof(e) <> 'string') THEN
                RETURN false;
            END IF;
        END LOOP;

        has_names  := (rule ? 'resource_names') AND jsonb_typeof(rule -> 'resource_names') <> 'null';
        has_labels := (rule ? 'match_labels')   AND jsonb_typeof(rule -> 'match_labels')   <> 'null';

        -- resource_names XOR match_labels (both → reject).
        IF has_names AND has_labels THEN RETURN false; END IF;

        IF has_names THEN
            IF jsonb_typeof(rule -> 'resource_names') <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'resource_names') > 256 THEN RETURN false; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements(rule -> 'resource_names') e
                       WHERE jsonb_typeof(e) <> 'string') THEN
                RETURN false;
            END IF;
        END IF;

        IF has_labels THEN
            IF jsonb_typeof(rule -> 'match_labels') <> 'object' THEN RETURN false; END IF;
            IF (SELECT count(*) FROM jsonb_object_keys(rule -> 'match_labels')) NOT BETWEEN 1 AND 16 THEN
                RETURN false;
            END IF;
        END IF;

        -- Вложенные правила (kaname#874). Ключа нет — правило без вложенных.
        IF rule ? 'children' THEN
            IF jsonb_typeof(rule -> 'children') <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'children') NOT BETWEEN 1 AND 16 THEN RETURN false; END IF;
            -- Владелец — ровно один ресурс, не подстановка, модуль не подстановка.
            IF rule ->> 'module' = '*' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'resources') <> 1 THEN RETURN false; END IF;
            IF rule -> 'resources' ->> 0 = '*' THEN RETURN false; END IF;

            FOR child IN SELECT value FROM jsonb_array_elements(rule -> 'children') LOOP
                IF jsonb_typeof(child) <> 'object' THEN RETURN false; END IF;
                -- Модуль — владельца; глубину выражает тип, а не структура роли.
                IF child ? 'module' OR child ? 'children' THEN RETURN false; END IF;
                FOR arr IN SELECT child -> k FROM (VALUES ('resources'), ('verbs')) AS t(k) LOOP
                    IF arr IS NULL OR jsonb_typeof(arr) <> 'array' THEN RETURN false; END IF;
                    IF jsonb_array_length(arr) < 1 OR jsonb_array_length(arr) > 16 THEN RETURN false; END IF;
                    IF EXISTS (SELECT 1 FROM jsonb_array_elements(arr) e WHERE jsonb_typeof(e) <> 'string') THEN
                        RETURN false;
                    END IF;
                END LOOP;
                -- Вложенное называет тип: не подстановку и не тип владельца.
                IF EXISTS (SELECT 1 FROM jsonb_array_elements_text(child -> 'resources') e
                            WHERE e = '*' OR e = rule -> 'resources' ->> 0) THEN
                    RETURN false;
                END IF;

                has_names  := (child ? 'resource_names') AND jsonb_typeof(child -> 'resource_names') <> 'null';
                has_labels := (child ? 'match_labels')   AND jsonb_typeof(child -> 'match_labels')   <> 'null';
                IF has_names AND has_labels THEN RETURN false; END IF;
                IF has_names THEN
                    IF jsonb_typeof(child -> 'resource_names') <> 'array' THEN RETURN false; END IF;
                    IF jsonb_array_length(child -> 'resource_names') > 256 THEN RETURN false; END IF;
                    IF EXISTS (SELECT 1 FROM jsonb_array_elements(child -> 'resource_names') e
                               WHERE jsonb_typeof(e) <> 'string') THEN
                        RETURN false;
                    END IF;
                END IF;
                IF has_labels THEN
                    IF jsonb_typeof(child -> 'match_labels') <> 'object' THEN RETURN false; END IF;
                    IF (SELECT count(*) FROM jsonb_object_keys(child -> 'match_labels')) NOT BETWEEN 1 AND 16 THEN
                        RETURN false;
                    END IF;
                END IF;
            END LOOP;
        END IF;
    END LOOP;

    RETURN true;
END;
$$;
-- +goose StatementEnd

ALTER TABLE kaname.role_rule_selectors
    DROP CONSTRAINT role_rule_selectors_creator_is_top_anchor_ck,
    DROP COLUMN created_by_subject;

DROP TRIGGER service_account_creator_is_immutable ON kaname.service_accounts;
DROP FUNCTION kaname.service_account_creator_is_immutable();
DROP INDEX kaname.service_accounts_creator_idx;
ALTER TABLE kaname.service_accounts
    DROP CONSTRAINT service_accounts_creator_id_nonempty_ck,
    DROP CONSTRAINT service_accounts_creator_type_ck,
    DROP CONSTRAINT service_accounts_creator_pair_ck,
    DROP COLUMN created_by_id,
    DROP COLUMN created_by_type;

ALTER TABLE kaname.catalog_verb
    DROP CONSTRAINT catalog_verb_container_relation_form_ck,
    DROP CONSTRAINT catalog_verb_container_is_tier_ck,
    DROP CONSTRAINT catalog_verb_container_pair_ck,
    DROP COLUMN container_relation,
    DROP COLUMN container_parent;
