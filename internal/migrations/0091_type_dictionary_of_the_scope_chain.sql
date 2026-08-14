-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 0091_type_dictionary_of_the_scope_chain — цепь областей говорит СЛОВАРЁМ МОДЕЛИ,
-- и это закреплено проверкой схемы, а не намерением писателя.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ
--
-- Имя типа названо в iam двумя словарями: словарём МОДЕЛИ ПРАВ (`vpc_network`,
-- `account`, `project`, `cluster`) и словарём КАТАЛОГА ресурсов (`vpc.network`,
-- `iam.account`). Вопрос о доступе приходит первым; зеркало и проекции ролей
-- названы вторым.
--
-- Цепь областей соединяется с ЧЕТЫРЬМЯ колонками: `relation_fact.object_type`,
-- `access_bindings.resource_type` и обеими сторонами собственной таблицы. Три из
-- четырёх названы словарём модели, а `resource_parent_edge.object_type` писался
-- словарём каталога — он приезжал из строки зеркала. Соединение по разным
-- написаниям не совпадает НИКОГДА и молча: выдача, сделанная на проект или
-- аккаунт, до ресурса не доходит, и отказ неотличим от честного.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ СЛОВАРЬ МОДЕЛИ, А НЕ КАТАЛОГА
--
-- Обратное направление невозможно ПО ПОСТРОЕНИЮ, а не по вкусу: вершина
-- иерархии `cluster` в каталоге ресурсов отсутствует — кластер не ресурс, — и
-- цепь, названная словарём каталога, не смогла бы дойти до строки администратора
-- облака вовсе. Плюс перевод пришлось бы делать над КОЛОНКАМИ двух других
-- таблиц, а не над одним параметром запроса.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЗДЕСЬ ЕСТЬ ПЕРЕЧЕНЬ ПАР — И ОН НЕ ВТОРОЕ МЕСТО ОБ ОДНОМ ПРЕДМЕТЕ
--
-- Перевод в дереве живёт в ОДНОМ месте (`internal/authzmap`). Ниже не второй
-- переводчик, а СНИМОК: пары, которые могли попасть в уже записанные строки. Он
-- одноразовый и самопроверяемый — после перевода миграция ОТКАЗЫВАЕТСЯ
-- завершиться, если хоть одна строка осталась в словаре каталога, и называет
-- значение. Тип, заведённый позже, строк в старом словаре не имел и иметь не
-- мог: писатель с этого изменения кладёт только словарь модели.
--
-- Признак словаря СТРУКТУРНЫЙ, а не списочный: точка есть у имени каталога
-- всегда и у имени модели никогда (в имени типа модели допустимы только буквы,
-- цифры, `_` и `-`). На нём же стоят проверки схемы ниже и снятие двойников
-- шагом (1) — оно мапы не требует вовсе. Само свойство утверждается по каталогу
-- целиком пробой `authzmap.TestOnlyTheCatalogDictionaryUsesADot`: первый тип,
-- его нарушивший, краснеет там, рядом с объяснением, а не отказом вставки на
-- поднятом стенде.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧЕГО ЭТА МИГРАЦИЯ НЕ ДЕЛАЕТ
--
-- Не трогает `access_bindings.resource_type`. Колонка тоже словаря модели, но её
-- заполняет граница API из закрытого словаря контракта, а история её строк
-- старше этого поколения таблиц; проверка схемы на ней — отдельное изменение со
-- своим замером, а не побочный эффект этого.

-- +goose Up

-- (1) Двойник. Строка словаря каталога, у которой для той же пары
--     (объект, глубина) уже есть строка словаря модели, снимается: перевод дал бы
--     конфликт первичного ключа, а двойник точнее — его записал исправленный
--     писатель. Мапа здесь не нужна: у объекта ровно один тип, поэтому строка с
--     тем же объектом и глубиной и БЕЗ точки в типе и есть его двойник.
DELETE FROM kacho_iam.resource_parent_edge stale
 WHERE stale.object_type LIKE '%.%'
   AND EXISTS (
     SELECT 1
       FROM kacho_iam.resource_parent_edge twin
      WHERE twin.object_id   = stale.object_id
        AND twin.depth       = stale.depth
        AND twin.object_type NOT LIKE '%.%'
   );

-- (2) Перевод обеих сторон ОДНИМ проходом: перечень пар написан здесь один раз.
--     Родительская сторона переводится тоже — владелец ресурса шлёт её словарём
--     модели, но цепь произвольной формы могла принести звено, записанное
--     строкой зеркала.
WITH d(catalog_name, model_name) AS (VALUES
    ('compute.instance',                 'compute_instance'),
    ('compute.guestAccessKey',           'compute_guest_access_key'),
    ('compute.placementGroup',           'compute_placement_group'),
    ('vpc.network',                      'vpc_network'),
    ('vpc.subnet',                       'vpc_subnet'),
    ('vpc.address',                      'vpc_address'),
    ('vpc.securityGroup',                'vpc_security_group'),
    ('vpc.routeTable',                   'vpc_route_table'),
    ('vpc.gateway',                      'vpc_gateway'),
    ('vpc.networkInterface',             'vpc_network_interface'),
    ('vpc.addressPool',                  'vpc_address_pool'),
    ('vpc.cidrGroup',                    'vpc_cidr_group'),
    ('loadbalancer.networkLoadBalancers','nlb_network_load_balancer'),
    ('loadbalancer.targetGroups',        'nlb_target_group'),
    ('loadbalancer.listeners',           'nlb_listener'),
    ('registry.registries',              'registry_registry'),
    ('registry.repositories',            'registry_repository'),
    ('storage.volumes',                  'storage_volume'),
    ('storage.snapshots',                'storage_snapshot'),
    ('storage.images',                   'storage_image'),
    ('iam.account',                      'account'),
    ('iam.project',                      'project'),
    ('iam.user',                         'iam_user'),
    ('iam.serviceAccount',               'iam_service_account'),
    ('iam.group',                        'iam_group'),
    ('iam.role',                         'iam_role'),
    ('iam.accessBinding',                'iam_access_binding')
)
UPDATE kacho_iam.resource_parent_edge e
   SET object_type = COALESCE(
         (SELECT d.model_name FROM d WHERE d.catalog_name = e.object_type), e.object_type),
       parent_type = COALESCE(
         (SELECT d.model_name FROM d WHERE d.catalog_name = e.parent_type), e.parent_type)
 WHERE e.object_type LIKE '%.%' OR e.parent_type LIKE '%.%';

-- (3) САМОПРОВЕРКА. Строка, оставшаяся в словаре каталога, означает, что снимок
--     чего-то не знал. Миграция отказывается завершиться и НАЗЫВАЕТ значение:
--     отказ дешевле молчаливого пропуска — пропущенная строка стала бы объектом
--     без предков, то есть отказом в доступе при живой выдаче.
-- +goose StatementBegin
DO $$
DECLARE leftover text;
BEGIN
  SELECT object_type || ' / ' || parent_type INTO leftover
    FROM kacho_iam.resource_parent_edge
   WHERE object_type LIKE '%.%' OR parent_type LIKE '%.%'
   LIMIT 1;
  IF leftover IS NOT NULL THEN
    RAISE EXCEPTION
      'resource_parent_edge: строка осталась в словаре каталога (%). Цепь областей читается словарём модели прав, и такая строка не совпадёт ни с одним вопросом о доступе. Добавьте пару в перечень этой миграции.', leftover;
  END IF;
END $$;
-- +goose StatementEnd

-- (4) ИНВАРИАНТ НА УРОВНЕ СХЕМЫ, а не в коде. Регрессия писателя отвергается
--     строкой и называет себя; программная проверка «посмотреть перед записью»
--     дала бы то же самое одним писателем позже и молча.
ALTER TABLE kacho_iam.resource_parent_edge
  ADD CONSTRAINT resource_parent_edge_object_type_model_dictionary
  CHECK (object_type NOT LIKE '%.%');

ALTER TABLE kacho_iam.resource_parent_edge
  ADD CONSTRAINT resource_parent_edge_parent_type_model_dictionary
  CHECK (parent_type NOT LIKE '%.%');

-- Тот же инвариант у прямого факта: его объект приезжает именем модели из
-- кортежа отношения, и цепь соединяется с ним ровно так же.
ALTER TABLE kacho_iam.relation_fact
  ADD CONSTRAINT relation_fact_object_type_model_dictionary
  CHECK (object_type NOT LIKE '%.%');

COMMENT ON COLUMN kacho_iam.resource_parent_edge.object_type IS
  'Тип объекта в словаре МОДЕЛИ ПРАВ (vpc_network, account, cluster) — тем же, каким приходит вопрос о доступе и каким названы relation_fact.object_type и access_bindings.resource_type. НЕ словарь каталога (vpc.network): соединение по разным написаниям не совпадает никогда и молча.';

COMMENT ON COLUMN kacho_iam.resource_parent_edge.parent_type IS
  'Тип предка в словаре МОДЕЛИ ПРАВ. Один словарь с object_type: цепь поднимается вверх соединением этих двух колонок, и разные написания оборвали бы её на первом же шаге.';

COMMENT ON COLUMN kacho_iam.relation_fact.object_type IS
  'Тип объекта в словаре МОДЕЛИ ПРАВ — как в кортеже отношения, из которого факт записан.';

-- +goose Down

ALTER TABLE kacho_iam.relation_fact
  DROP CONSTRAINT IF EXISTS relation_fact_object_type_model_dictionary;
ALTER TABLE kacho_iam.resource_parent_edge
  DROP CONSTRAINT IF EXISTS resource_parent_edge_parent_type_model_dictionary;
ALTER TABLE kacho_iam.resource_parent_edge
  DROP CONSTRAINT IF EXISTS resource_parent_edge_object_type_model_dictionary;

COMMENT ON COLUMN kacho_iam.relation_fact.object_type IS NULL;
COMMENT ON COLUMN kacho_iam.resource_parent_edge.parent_type IS NULL;
COMMENT ON COLUMN kacho_iam.resource_parent_edge.object_type IS NULL;

-- Обратный перевод НЕ делается. Откат обязан возвращать состояние, а не обеднять
-- его, но словарь каталога в этой колонке был дефектом: строка, которую никто не
-- мог прочитать, не является состоянием, к которому стоит возвращаться.
