-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- membership_is_an_authz_object — ЧЛЕНСТВО становится объектом модели прав
-- (подфаза IAM-ID-1, S3.1; приёмка одобрена и СОБЫТИЙНА — отпечаток
-- c5937b4e…, событие kacho#1351).
--
-- =============================================================================
-- ЗАЧЕМ: ГЕЙТ ЧТЕНИЯ ЛИЧНОСТИ СКОУПИТСЯ НА ЧЛЕНСТВО
-- =============================================================================
-- Членство принадлежит РОВНО ОДНОМУ аккаунту, поэтому право резолвится в
-- пределах этого аккаунта. Скоупнутый на `iam_membership` гейт чтения
-- резолвится в пределах одного аккаунта by construction, а доступ
-- администратора своего аккаунта остаётся. Глобальная личность (`iam_user`)
-- такого сужения не даёт.
--
-- =============================================================================
-- АДРЕСАЦИЯ — СОБСТВЕННЫЙ НЕИЗМЕНЯЕМЫЙ id ЧЛЕНСТВА (ban #15)
-- =============================================================================
-- Объект гейта — `iam_membership:<mbr-…>`, где `mbr-…` это `memberships.id`:
-- уже посаженная координата с ограничением формы
-- (`memberships_id_form_check`), неизменяемая на всю жизнь строки. Край берёт
-- её из поля запроса `membership_id` — деривация читает ОДНО поле верхнего
-- уровня и склеивает объект как `<object_type>:<id>`.
--
-- Композит `<account>:<user>` РАССМОТРЕН И ОТВЕРГНУТ: он потребовал бы
-- расширить арность деривации в ФУНДАМЕНТЕ (прецедентов ноль), а у членства уже
-- есть стабильный id — ban #15 велит ключевать authz-цель им, а не парой.
--
-- =============================================================================
-- ЧТО ЗДЕСЬ ДЕЛАЕТСЯ
-- =============================================================================
-- (1) Строки каталога для пары `iam.membership` — тип становится ЖИВЫМ
--     ресурсом платформы. Без них проекция селекторов роли-владельца отвергается
--     ключом `role_rule_selectors.object_types` (23514: «is not a live platform
--     resource»), а страж старта расходится с литералом `authzmap`.
--     Глаголы: `get`/`list` пообъектно (тип объявляет `v_get`/`v_list`) плюс
--     ярусный `create` — у класса «создать» пообъектного референта нет by
--     construction, и производитель посева кладёт его ярусным всем ресурсам.
--
-- (2) Дописывание посеянных селекторов системных ролей: подстановка `*.*`
--     разворачивается в набор материализуемых типов, и `iam.membership` в него
--     вошёл. Набор посеян ЛИТЕРАЛОМ (SQL не считает sha256 отпечатка правила),
--     поэтому его дописывает миграция — в шаге с Go-проекцией, который держит
--     гейт `TestOwnerRoleSelector_MigrationLockstep`.
--
-- (3) Ветвь цепи областей для `iam_membership`. Предок — ЕДИНСТВЕННЫЙ аккаунт
--     членства (`o.account_id`), объект адресуется СВОИМ `o.id`: ветвь берёт
--     объектом строку членства, и этим отличается от ветви `iam_user` ниже,
--     которая берёт объектом `m.user_id`.
--
-- ПРЕДСТАВЛЕНИЕ ПЕРЕОПРЕДЕЛЯЕТСЯ ЦЕЛИКОМ (`CREATE OR REPLACE`), потому что
-- ветвь добавляется в `UNION ALL`: дописать её к существующему определению
-- нечем. Все прежние ветви воспроизведены ДОСЛОВНО из применённой миграции —
-- применённую не правят (запрет #5), поэтому расхождение здесь было бы молчаливым.
--
-- ЧЕГО ЗДЕСЬ НЕТ. Материализация кортежей области по членству (реконсайлер) в
-- эту миграцию не входит: её предмет — схема и словарь, а не выдача. Её кладёт
-- отдельная полоса, и до неё объект существует, но кортежей на нём нет.

-- +goose Up

-- (1) Словарь: пара `iam.membership` и её глаголы.
INSERT INTO kaname.catalog_resource (module, resource, dotted, object_type) VALUES ('iam', 'membership', 'iam.membership', 'iam_membership');

INSERT INTO kaname.catalog_verb (module, resource, verb, per_object) VALUES
    ('iam', 'membership', 'get', true),
    ('iam', 'membership', 'list', true),
    ('iam', 'membership', 'create', false);

-- (2) Проекция селекторов: подстановка `*.*` системных ролей разворачивается в
--     НАБОР МАТЕРИАЛИЗУЕМЫХ ТИПОВ, и `iam.membership` в него вошёл. Посеянные
--     строки несут набор литералом (SQL не считает sha256 отпечатка правила),
--     поэтому их дописывает миграция — в шаге с Go-проекцией, который держит
--     гейт `domain` `TestOwnerRoleSelector_MigrationLockstep`.
--
--     Порядок несущий: строка каталога выше УЖЕ вставлена, иначе ключ
--     `role_rule_selectors.object_types` отверг бы набор (23514, «is not a live
--     platform resource»).
--
--     Идемпотентно: строка, уже несущая тип, не трогается. Набор пересобирается
--     ОТСОРТИРОВАННЫМ — порядок в нём часть литерала, с которым сверяется гейт.
UPDATE kaname.role_rule_selectors
   SET object_types = (SELECT array_agg(t ORDER BY t)
                         FROM unnest(object_types || ARRAY['iam.membership'::text]) AS t),
       updated_at = now()
 WHERE arm = 'anchor'
   AND NOT ('iam.membership' = ANY (object_types))
   AND object_types @> ARRAY['iam.account'::text, 'iam.project'::text, 'iam.user'::text,
                             'iam.group'::text, 'iam.role'::text, 'iam.serviceAccount'::text,
                             'iam.accessBinding'::text];

-- (3) Цепь областей: у членства ровно один предок-аккаунт, объект — его `id`.
CREATE OR REPLACE VIEW kaname.resource_scope_edge AS
 SELECT e.object_type,
    e.object_id,
    e.parent_type,
    e.parent_id,
    e.depth
   FROM kaname.resource_parent_edge e
UNION ALL
 SELECT 'project'::text AS object_type,
    f.object_id,
    split_part(f.subject, ':'::text, 1) AS parent_type,
    substr(f.subject, (POSITION((':'::text) IN (f.subject)) + 1)) AS parent_id,
    1 AS depth
   FROM kaname.relation_fact f
  WHERE ((f.object_type = 'project'::text) AND (f.relation = split_part(f.subject, ':'::text, 1)) AND (POSITION(('#'::text) IN (f.subject)) = 0) AND (NOT (EXISTS ( SELECT 1
           FROM kaname.resource_parent_edge e
          WHERE ((e.object_type = 'project'::text) AND (e.object_id = f.object_id))))))
UNION ALL
 SELECT 'account'::text AS object_type,
    a.id AS object_id,
    'cluster'::text AS parent_type,
    c.id AS parent_id,
    1 AS depth
   FROM (kaname.accounts a
     CROSS JOIN kaname.clusters c)
  WHERE (NOT (EXISTS ( SELECT 1
           FROM kaname.resource_parent_edge e
          WHERE ((e.object_type = 'account'::text) AND (e.object_id = a.id)))))
UNION ALL
 SELECT 'iam_user'::text AS object_type,
    m.user_id AS object_id,
    'account'::text AS parent_type,
    m.account_id AS parent_id,
    1 AS depth
   FROM kaname.memberships m
  WHERE ((COALESCE(m.account_id, ''::text) <> ''::text) AND (NOT (EXISTS ( SELECT 1
           FROM kaname.resource_parent_edge e
          WHERE ((e.object_type = 'iam_user'::text) AND (e.object_id = m.user_id))))))
UNION ALL
 SELECT 'iam_group'::text AS object_type,
    o.id AS object_id,
    'account'::text AS parent_type,
    o.account_id AS parent_id,
    1 AS depth
   FROM kaname.groups o
  WHERE ((COALESCE(o.account_id, ''::text) <> ''::text) AND (NOT (EXISTS ( SELECT 1
           FROM kaname.resource_parent_edge e
          WHERE ((e.object_type = 'iam_group'::text) AND (e.object_id = o.id))))))
UNION ALL
 SELECT 'iam_service_account'::text AS object_type,
    o.id AS object_id,
    'account'::text AS parent_type,
    o.account_id AS parent_id,
    1 AS depth
   FROM kaname.service_accounts o
  WHERE ((COALESCE(o.account_id, ''::text) <> ''::text) AND (NOT (EXISTS ( SELECT 1
           FROM kaname.resource_parent_edge e
          WHERE ((e.object_type = 'iam_service_account'::text) AND (e.object_id = o.id))))))
UNION ALL
 SELECT 'iam_role'::text AS object_type,
    o.id AS object_id,
    'account'::text AS parent_type,
    o.account_id AS parent_id,
    1 AS depth
   FROM kaname.roles o
  WHERE ((COALESCE(o.account_id, ''::text) <> ''::text) AND (NOT (EXISTS ( SELECT 1
           FROM kaname.resource_parent_edge e
          WHERE ((e.object_type = 'iam_role'::text) AND (e.object_id = o.id))))))
UNION ALL
 SELECT 'iam_role'::text AS object_type,
    o.id AS object_id,
    'project'::text AS parent_type,
    o.project_id AS parent_id,
    1 AS depth
   FROM kaname.roles o
  WHERE ((COALESCE(o.project_id, ''::text) <> ''::text) AND (NOT (EXISTS ( SELECT 1
           FROM kaname.resource_parent_edge e
          WHERE ((e.object_type = 'iam_role'::text) AND (e.object_id = o.id))))))
UNION ALL
 SELECT 'iam_access_binding'::text AS object_type,
    o.id AS object_id,
    lower(o.resource_type) AS parent_type,
    o.resource_id AS parent_id,
    1 AS depth
   FROM kaname.access_bindings o
  WHERE ((lower(o.resource_type) = ANY (ARRAY['project'::text, 'account'::text, 'cluster'::text])) AND (COALESCE(o.resource_id, ''::text) <> ''::text) AND (NOT (EXISTS ( SELECT 1
           FROM kaname.resource_parent_edge e
          WHERE ((e.object_type = 'iam_access_binding'::text) AND (e.object_id = o.id))))))
UNION ALL
 SELECT 'iam_membership'::text AS object_type,
    o.id AS object_id,
    'account'::text AS parent_type,
    o.account_id AS parent_id,
    1 AS depth
   FROM kaname.memberships o
  WHERE ((COALESCE(o.account_id, ''::text) <> ''::text) AND (NOT (EXISTS ( SELECT 1
           FROM kaname.resource_parent_edge e
          WHERE ((e.object_type = 'iam_membership'::text) AND (e.object_id = o.id))))));


-- +goose Down

CREATE OR REPLACE VIEW kaname.resource_scope_edge AS
 SELECT e.object_type,
    e.object_id,
    e.parent_type,
    e.parent_id,
    e.depth
   FROM kaname.resource_parent_edge e
UNION ALL
 SELECT 'project'::text AS object_type,
    f.object_id,
    split_part(f.subject, ':'::text, 1) AS parent_type,
    substr(f.subject, (POSITION((':'::text) IN (f.subject)) + 1)) AS parent_id,
    1 AS depth
   FROM kaname.relation_fact f
  WHERE ((f.object_type = 'project'::text) AND (f.relation = split_part(f.subject, ':'::text, 1)) AND (POSITION(('#'::text) IN (f.subject)) = 0) AND (NOT (EXISTS ( SELECT 1
           FROM kaname.resource_parent_edge e
          WHERE ((e.object_type = 'project'::text) AND (e.object_id = f.object_id))))))
UNION ALL
 SELECT 'account'::text AS object_type,
    a.id AS object_id,
    'cluster'::text AS parent_type,
    c.id AS parent_id,
    1 AS depth
   FROM (kaname.accounts a
     CROSS JOIN kaname.clusters c)
  WHERE (NOT (EXISTS ( SELECT 1
           FROM kaname.resource_parent_edge e
          WHERE ((e.object_type = 'account'::text) AND (e.object_id = a.id)))))
UNION ALL
 SELECT 'iam_user'::text AS object_type,
    m.user_id AS object_id,
    'account'::text AS parent_type,
    m.account_id AS parent_id,
    1 AS depth
   FROM kaname.memberships m
  WHERE ((COALESCE(m.account_id, ''::text) <> ''::text) AND (NOT (EXISTS ( SELECT 1
           FROM kaname.resource_parent_edge e
          WHERE ((e.object_type = 'iam_user'::text) AND (e.object_id = m.user_id))))))
UNION ALL
 SELECT 'iam_group'::text AS object_type,
    o.id AS object_id,
    'account'::text AS parent_type,
    o.account_id AS parent_id,
    1 AS depth
   FROM kaname.groups o
  WHERE ((COALESCE(o.account_id, ''::text) <> ''::text) AND (NOT (EXISTS ( SELECT 1
           FROM kaname.resource_parent_edge e
          WHERE ((e.object_type = 'iam_group'::text) AND (e.object_id = o.id))))))
UNION ALL
 SELECT 'iam_service_account'::text AS object_type,
    o.id AS object_id,
    'account'::text AS parent_type,
    o.account_id AS parent_id,
    1 AS depth
   FROM kaname.service_accounts o
  WHERE ((COALESCE(o.account_id, ''::text) <> ''::text) AND (NOT (EXISTS ( SELECT 1
           FROM kaname.resource_parent_edge e
          WHERE ((e.object_type = 'iam_service_account'::text) AND (e.object_id = o.id))))))
UNION ALL
 SELECT 'iam_role'::text AS object_type,
    o.id AS object_id,
    'account'::text AS parent_type,
    o.account_id AS parent_id,
    1 AS depth
   FROM kaname.roles o
  WHERE ((COALESCE(o.account_id, ''::text) <> ''::text) AND (NOT (EXISTS ( SELECT 1
           FROM kaname.resource_parent_edge e
          WHERE ((e.object_type = 'iam_role'::text) AND (e.object_id = o.id))))))
UNION ALL
 SELECT 'iam_role'::text AS object_type,
    o.id AS object_id,
    'project'::text AS parent_type,
    o.project_id AS parent_id,
    1 AS depth
   FROM kaname.roles o
  WHERE ((COALESCE(o.project_id, ''::text) <> ''::text) AND (NOT (EXISTS ( SELECT 1
           FROM kaname.resource_parent_edge e
          WHERE ((e.object_type = 'iam_role'::text) AND (e.object_id = o.id))))))
UNION ALL
 SELECT 'iam_access_binding'::text AS object_type,
    o.id AS object_id,
    lower(o.resource_type) AS parent_type,
    o.resource_id AS parent_id,
    1 AS depth
   FROM kaname.access_bindings o
  WHERE ((lower(o.resource_type) = ANY (ARRAY['project'::text, 'account'::text, 'cluster'::text])) AND (COALESCE(o.resource_id, ''::text) <> ''::text) AND (NOT (EXISTS ( SELECT 1
           FROM kaname.resource_parent_edge e
          WHERE ((e.object_type = 'iam_access_binding'::text) AND (e.object_id = o.id))))));

DELETE FROM kaname.catalog_verb WHERE module = 'iam' AND resource = 'membership';

DELETE FROM kaname.catalog_resource WHERE module = 'iam' AND resource = 'membership';
