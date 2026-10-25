-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- grant_delegations — делегирование права выдавать (задача PRO-Robotech/kaname#986).
--
-- САНКЦИЯ: приёмка docs/engineering/acceptance/delegated-grants-stay-within-the-delegation.md,
-- редакция 3, отпечаток одобренной редакции
-- 7512fd96c7aeb85f352fd55954cfb881fa7c8610169574adb2291155bb690fe6 (записи ревью —
-- docs/specs/reviews/delegated-grants-stay-within-the-delegation/).
--
-- ЧТО МЕНЯЕТСЯ:
--
--   1. `kaname.grant_delegations` — делегирование: аккаунт, делегат (служебная
--      учётка), оси (роли, типы цели, типы субъекта), модуль, состояние и кто
--      завёл и отозвал. Оси неизменяемы; отозванная строка остаётся для аудита,
--      метода удаления у делегирования нет.
--   2. `grant_delegations_active_pair_uniq` — одно ДЕЙСТВУЮЩЕЕ делегирование на
--      пару «аккаунт, делегат» (Д1): частичная уникальность по `status = 'ACTIVE'`.
--      Второе заведение пары — 23505, обработчик отвечает ALREADY_EXISTS.
--   3. `active_delegate_id` — ссылка на учётку-делегата, заданная ТОЛЬКО у
--      действующей строки; отзыв её обнуляет (`grant_delegations_active_delegate_ck`).
--      Внешний ключ `ON DELETE RESTRICT` держит учётку, пока делегирование
--      действует (Д8), и не держит её после отзыва: учётку снимает жёсткий DELETE,
--      а отозванные строки живут для аудита, поэтому ключ на неизменяемой колонке
--      делегата держал бы учётку навсегда. NULL ключ не судит (MATCH SIMPLE).
--   4. `account_id` — без внешнего ключа, как `access_bindings.resource_id`:
--      исход удаления аккаунта эта задача не меняет (§2 п.6 приёмки).
--   5. `access_bindings.delegation_id` — делегирование, по которому выдача сделана
--      делегатом; NULL у выдачи держателя права выдавать. Внешний ключ на
--      `grant_delegations(id)` (метода удаления у делегирования нет) и частичный
--      индекс по действующим выдачам — под отбор отзыва делегирования.
--   6. `access_bindings_revocation_reason_ck` — четвёртое значение причины отзыва
--      `DELEGATION_REVOKED` (Р4).
--
-- ОТКАТ снимает колонку, таблицу и возвращает прежнее ограничение причины дословно.
-- Откат отказывает, пока лежит выдача с причиной `DELEGATION_REVOKED`: прежнее
-- ограничение её не принимает, и молча переписать причину нечем.

-- +goose Up

CREATE TABLE kaname.grant_delegations (
    id text NOT NULL,
    account_id text NOT NULL,
    delegate_id text NOT NULL,
    active_delegate_id text,
    role_ids text[] NOT NULL,
    target_types text[] NOT NULL,
    subject_types text[] NOT NULL,
    module text NOT NULL,
    status text NOT NULL,
    delegated_by_type text NOT NULL,
    delegated_by_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    revoked_by_type text,
    revoked_by_id text,
    CONSTRAINT grant_delegations_pkey PRIMARY KEY (id),
    CONSTRAINT grant_delegations_active_delegate_fk FOREIGN KEY (active_delegate_id)
        REFERENCES kaname.service_accounts (id) ON DELETE RESTRICT,
    CONSTRAINT grant_delegations_status_ck CHECK (status = ANY (ARRAY['ACTIVE'::text, 'REVOKED'::text])),
    CONSTRAINT grant_delegations_revoked_consistency_ck CHECK (
        (status = 'ACTIVE' AND revoked_at IS NULL AND revoked_by_type IS NULL AND revoked_by_id IS NULL)
        OR (status = 'REVOKED' AND revoked_at IS NOT NULL
            AND COALESCE(revoked_by_type, '') <> '' AND COALESCE(revoked_by_id, '') <> '')
    ),
    CONSTRAINT grant_delegations_active_delegate_ck CHECK (
        (status = 'ACTIVE' AND active_delegate_id = delegate_id)
        OR (status = 'REVOKED' AND active_delegate_id IS NULL)
    ),
    CONSTRAINT grant_delegations_axes_ck CHECK (
        cardinality(role_ids) BETWEEN 1 AND 16
        AND cardinality(target_types) BETWEEN 1 AND 16
        AND cardinality(subject_types) BETWEEN 1 AND 4
    ),
    CONSTRAINT grant_delegations_subject_types_ck CHECK (
        subject_types <@ ARRAY['user'::text, 'service_account'::text, 'group'::text, 'system_class'::text]
    ),
    CONSTRAINT grant_delegations_module_ck CHECK (module <> '' AND module <> 'iam'),
    CONSTRAINT grant_delegations_ids_nonempty_ck CHECK (
        account_id <> '' AND delegate_id <> '' AND delegated_by_type <> '' AND delegated_by_id <> ''
    )
);

COMMENT ON TABLE kaname.grant_delegations IS
    'Делегирование права выдавать (kaname#986): служебная учётка выдаёт роли одного модуля на его объекты в одном аккаунте от имени делегирующего.';
COMMENT ON COLUMN kaname.grant_delegations.active_delegate_id IS
    'Учётка-делегат, пока делегирование действует; NULL после отзыва. Держит учётку от удаления (Д8) только у действующей строки.';

CREATE UNIQUE INDEX grant_delegations_active_pair_uniq ON kaname.grant_delegations
    USING btree (account_id, delegate_id)
    WHERE (status = 'ACTIVE');

-- Курсор перечня `(created_at, id)` — той же формы, что у соседних таблиц
-- (`groups_cursor_idx`, `projects_cursor_idx`), и аккаунт — отдельным индексом.
CREATE INDEX grant_delegations_cursor_idx ON kaname.grant_delegations
    USING btree (created_at, id);

CREATE INDEX grant_delegations_account_idx ON kaname.grant_delegations
    USING btree (account_id);

ALTER TABLE kaname.access_bindings
    ADD COLUMN delegation_id text;

ALTER TABLE kaname.access_bindings
    ADD CONSTRAINT access_bindings_delegation_fk FOREIGN KEY (delegation_id)
        REFERENCES kaname.grant_delegations (id);

COMMENT ON COLUMN kaname.access_bindings.delegation_id IS
    'Делегирование, по которому выдачу сделал делегат (kaname#986); NULL у выдачи держателя права выдавать. Ставит только делегированный путь права выдавать.';

CREATE INDEX access_bindings_delegation_live_idx ON kaname.access_bindings
    USING btree (delegation_id)
    WHERE ((delegation_id IS NOT NULL) AND (revoked_at IS NULL));

ALTER TABLE kaname.access_bindings DROP CONSTRAINT access_bindings_revocation_reason_ck;
ALTER TABLE kaname.access_bindings
    ADD CONSTRAINT access_bindings_revocation_reason_ck CHECK (
        revocation_reason IS NULL
        OR (status = 'REVOKED'
            AND revocation_reason = ANY (ARRAY['REVOKE'::text, 'EXPIRED'::text, 'RESOURCE_UNREGISTERED'::text,
                                               'DELEGATION_REVOKED'::text]))
    );

COMMENT ON COLUMN kaname.access_bindings.revocation_reason IS
    'Почему выдача отозвана: REVOKE | EXPIRED | RESOURCE_UNREGISTERED | DELEGATION_REVOKED (kaname#963, Д2; kaname#986, Р4). NULL у действующей и у отозванной до заведения колонки (Д7).';

-- +goose Down

ALTER TABLE kaname.access_bindings DROP CONSTRAINT access_bindings_revocation_reason_ck;
ALTER TABLE kaname.access_bindings
    ADD CONSTRAINT access_bindings_revocation_reason_ck CHECK (
        revocation_reason IS NULL
        OR (status = 'REVOKED'
            AND revocation_reason = ANY (ARRAY['REVOKE'::text, 'EXPIRED'::text, 'RESOURCE_UNREGISTERED'::text]))
    );

COMMENT ON COLUMN kaname.access_bindings.revocation_reason IS
    'Почему выдача отозвана: REVOKE | EXPIRED | RESOURCE_UNREGISTERED (kaname#963, Д2). NULL у действующей и у отозванной до заведения колонки (Д7).';

DROP INDEX kaname.access_bindings_delegation_live_idx;
ALTER TABLE kaname.access_bindings DROP CONSTRAINT access_bindings_delegation_fk;
ALTER TABLE kaname.access_bindings DROP COLUMN delegation_id;

DROP TABLE kaname.grant_delegations;
