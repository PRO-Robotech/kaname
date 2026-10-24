-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- unregistration_revokes_its_grants — снятие регистрации объекта снимает его
-- выдачи (задача PRO-Robotech/kaname#963).
--
-- САНКЦИЯ: приёмка docs/engineering/acceptance/unregistration-revokes-its-grants.md,
-- редакция 2, отпечаток одобренной редакции
-- 0743cd4f3f4ac1b9519870bce93475a339c7729f202ee6cc1ad5386a87bd97b4 (записи ревью —
-- docs/specs/reviews/unregistration-revokes-its-grants/).
--
-- ЧТО МЕНЯЕТСЯ:
--
--   1. `access_bindings.revocation_reason` — почему выдача отозвана, закрытым
--      словарём (Д2): `REVOKE` (глагол), `EXPIRED` (проход срока),
--      `RESOURCE_UNREGISTERED` (снятие регистрации объекта цели). Задана только
--      у отозванной выдачи (`access_bindings_revocation_reason_ck`, согласовано с
--      `access_bindings_revoked_consistency_ck`). Строки, отозванные до этой
--      миграции, несут NULL: причина не записывалась, а вывод её из
--      `revoked_by_user_id` был бы выводом из истории писателей, а не фактом
--      (Д7). Обратного заполнения нет.
--   2. `access_bindings.narrowed_at` — когда цель выдачи сузило снятие
--      регистрации (Р1 (б)). Наружу не проецируется; нужен индексу ниже.
--   3. `access_bindings_active_grant_uniq` — суженная выдача слот уникальности не
--      занимает, как отозванная (Д4): к условию `revoked_at IS NULL` добавлено
--      `narrowed_at IS NULL`.
--   4. `access_bindings_target_resources_live_idx` — поиск действующих выдач,
--      цель которых называет ключ, индексом, а не перебором выдач (критерий
--      производительности §3 приёмки).
--   5. `role_rule_selectors_resource_names_idx` — тот же поиск для названий
--      правил ролей (Р1 (д), Р7).
--   6. `roles_permissions_valid` — третья форма: `permissions = []` и
--      `rules = []`, роль, все правила которой потеряли адресатов снятием
--      регистрации (Р6). Такая роль не даёт ничего. Вход `RoleService.Create` и
--      `Update` по-прежнему требует 1..64 правил — это правило входа, а не схемы.
--
-- ОТКАТ возвращает прежние определения ограничения роли и индекса уникальности
-- дословно и снимает колонки. Откат отказывает, пока лежит роль третьей формы:
-- прежнее ограничение её не принимает, и молча переписать роль нечем.

-- +goose Up

ALTER TABLE kaname.access_bindings
    ADD COLUMN revocation_reason text,
    ADD COLUMN narrowed_at timestamp with time zone;

ALTER TABLE kaname.access_bindings
    ADD CONSTRAINT access_bindings_revocation_reason_ck CHECK (
        revocation_reason IS NULL
        OR (status = 'REVOKED'
            AND revocation_reason = ANY (ARRAY['REVOKE'::text, 'EXPIRED'::text, 'RESOURCE_UNREGISTERED'::text]))
    );

COMMENT ON COLUMN kaname.access_bindings.revocation_reason IS
    'Почему выдача отозвана: REVOKE | EXPIRED | RESOURCE_UNREGISTERED (kaname#963, Д2). NULL у действующей и у отозванной до заведения колонки (Д7).';
COMMENT ON COLUMN kaname.access_bindings.narrowed_at IS
    'Когда цель выдачи сузило снятие регистрации объекта (kaname#963, Р1 (б)). Суженная выдача слот уникальности не занимает (Д4).';

DROP INDEX kaname.access_bindings_active_grant_uniq;
CREATE UNIQUE INDEX access_bindings_active_grant_uniq ON kaname.access_bindings
    USING btree (subject_id, subject_type, role_id, resource_type, resource_id, target_digest)
    WHERE ((revoked_at IS NULL) AND (narrowed_at IS NULL));

CREATE INDEX access_bindings_target_resources_live_idx ON kaname.access_bindings
    USING gin ((target -> 'resources') jsonb_path_ops)
    WHERE (revoked_at IS NULL);

CREATE INDEX role_rule_selectors_resource_names_idx ON kaname.role_rule_selectors
    USING gin (resource_names);

ALTER TABLE kaname.roles DROP CONSTRAINT roles_permissions_valid;
ALTER TABLE kaname.roles
    ADD CONSTRAINT roles_permissions_valid CHECK (
        ((jsonb_array_length(permissions) = 0) AND (jsonb_array_length(rules) > 0))
        OR ((jsonb_array_length(permissions) = 0) AND (jsonb_array_length(rules) = 0))
        OR kaname.iam_permissions_valid(permissions)
    );

-- +goose Down

ALTER TABLE kaname.roles DROP CONSTRAINT roles_permissions_valid;
ALTER TABLE kaname.roles
    ADD CONSTRAINT roles_permissions_valid CHECK ((((jsonb_array_length(permissions) = 0) AND (jsonb_array_length(rules) > 0)) OR kaname.iam_permissions_valid(permissions)));

DROP INDEX kaname.role_rule_selectors_resource_names_idx;
DROP INDEX kaname.access_bindings_target_resources_live_idx;

DROP INDEX kaname.access_bindings_active_grant_uniq;
CREATE UNIQUE INDEX access_bindings_active_grant_uniq ON kaname.access_bindings USING btree (subject_id, subject_type, role_id, resource_type, resource_id, target_digest) WHERE (revoked_at IS NULL);

ALTER TABLE kaname.access_bindings DROP CONSTRAINT access_bindings_revocation_reason_ck;
ALTER TABLE kaname.access_bindings
    DROP COLUMN narrowed_at,
    DROP COLUMN revocation_reason;
