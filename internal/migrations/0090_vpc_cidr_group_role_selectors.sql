-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- Ввести `vpc.cidrGroup` (именованный набор префиксов) в материализующие
-- селекторы системных ролей.
--
-- ПРЕДМЕТ. Тип `vpc_cidr_group` объявлен в модели прав со всеми глаголами и
-- регистрируется у владельца прав наравне с соседями (Create эмитит указатель
-- принадлежности с собственными labels). Не хватало ровно одного: dotted-ключа в
-- множестве раскрытия подстановки `domain.AllMaterializableTypes()` и, как
-- следствие, в `role_rule_selectors` — индексе, по которому подбор находит
-- привязку, материализующую пообъектные `v_*`. Без него привязка НЕВИДИМА
-- подбору: набор создаётся, кортеж принадлежности доезжает, а создатель с
-- project-охватом получает отказ на СВОЁМ свежем наборе
-- (`no authorization path to the resource`, действия `vpc.cidr_groups.update` /
-- `.delete`). Тот же класс, что #71 у storage (миграция 0060) — там он был
-- закрыт поэкземплярно, здесь его держит гейт
-- services/iam/internal/authzmap/verb_type_materializable_test.go: он требует
-- запись в проекции от КАЖДОГО глагольного типа модели.
--
-- ЗАЧЕМ МИГРАЦИЯ, ЕСЛИ ЕСТЬ BOOT-BACKFILL. `seed.SyncAllSystemRoleSelectors`
-- пересчитывает `object_types` из Go-реестра при каждом старте iam, поэтому
-- развёрнутая база сойдётся и без этой миграции. Миграция всё равно нужна по
-- двум причинам: (1) до первого прохода backfill'а в базе лежит строка, которая
-- НЕВЕРНА, и это состояние операционно неотличимо от исходного дефекта; (2)
-- пара `rule_wildcard_scope_test.go` (Owner/SystemWildcard MigrationLockstep)
-- держит равенство «Go-проекция == константа миграции» и краснеет, пока
-- миграция не догнала реестр — то есть дисциплина этого дерева требует ровно
-- такой миграции на каждое расширение множества (0043 → 0053 → 0060 → 0074).
--
-- ФОРМА ПРАВКИ — ДОБАВЛЕНИЕ, А НЕ ПЕРЕПИСЬ. Прежние миграции этого ряда
-- перечисляли весь набор целиком по четыре раза в одном файле; каждое такое
-- перечисление — ещё одно место, где живёт один и тот же список, и 0074 уже
-- пришлось вычищать его `array_remove`. Здесь строка ДОПОЛНЯЕТСЯ одним
-- элементом, а набор перечислен ровно один раз — в ПРЕДИКАТЕ отбора строк.
--
-- ПРЕДИКАТ отбирает строки, чей `object_types` содержит ВЕСЬ прежний набор из
-- 23 типов, — это и есть признак «строка получена раскрытием подстановки `*.*`».
-- Он покрывает и четыре каталожные системные роли (admin/edit/view/owner), и
-- обе служебные (`rol000000000sys*`), и любую будущую роль, авторизованную
-- подстановкой, — и НЕ трогает узкую строку, где `vpc.securityGroup` (или любой
-- другой тип) назван явно: такая строка всех 23 не содержит, и её раскрывать
-- было бы расширением выдачи.
--
-- ПОРЯДОК ЭЛЕМЕНТОВ — байтовый (`COLLATE "C"`), а не по локали базы: Go-проекция
-- сортирует `sort.Strings`, и сравнение с ней в lockstep-пробе позиционное.
-- Локаль по умолчанию на этих строках дала бы тот же порядок, но зависеть от неё
-- значило бы держать равенство на совпадении, а не на определении.
--
-- ИДЕМПОТЕНТНО: `DISTINCT` + предикат `NOT @> ARRAY['vpc.cidrGroup']` — повторный
-- прогон (и самолечение backfill'ом на старте) ничего не меняет. Аддитивно;
-- применённые миграции не редактируются (запрет #5). Следующая миграция: 0089.

-- +goose Up
-- +goose StatementBegin

UPDATE kacho_iam.role_rule_selectors
   SET object_types = ARRAY(
         -- DISTINCT и ORDER BY разнесены по уровням намеренно: Postgres требует,
         -- чтобы выражение сортировки стояло в списке выборки SELECT DISTINCT, а
         -- `ty COLLATE "C"` — именно выражение. Первая редакция этого стейтмента
         -- падала на 42P10 — на СТАРТЕ init-контейнера, а не молча: сервис не
         -- поднялся, прежний под остался обслуживать. Это правильный исход
         -- (fail-closed), и он назван здесь, чтобы следующий не «упростил» обратно.
         SELECT ty
           FROM (
             SELECT DISTINCT unnest(object_types || ARRAY['vpc.cidrGroup']::text[]) AS ty
           ) s
          ORDER BY ty COLLATE "C"
       ),
       updated_at = now()
 WHERE object_types @> ARRAY[
         'compute.instance',
         'iam.accessBinding', 'iam.account', 'iam.group', 'iam.project',
         'iam.role', 'iam.serviceAccount', 'iam.user',
         'loadbalancer.listeners', 'loadbalancer.networkLoadBalancers', 'loadbalancer.targetGroups',
         'registry.registries', 'registry.repositories',
         'storage.images', 'storage.snapshots', 'storage.volumes',
         'vpc.address', 'vpc.gateway', 'vpc.network', 'vpc.networkInterface',
         'vpc.routeTable', 'vpc.securityGroup', 'vpc.subnet'
       ]::text[]
   AND NOT object_types @> ARRAY['vpc.cidrGroup']::text[];

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Снять элемент с тех же строк. `array_remove` на строке, где его нет, — no-op,
-- поэтому предикат нужен только чтобы не трогать `updated_at` без дела.
UPDATE kacho_iam.role_rule_selectors
   SET object_types = array_remove(object_types, 'vpc.cidrGroup'),
       updated_at   = now()
 WHERE object_types @> ARRAY['vpc.cidrGroup']::text[]
   AND array_length(object_types, 1) > 1;

-- +goose StatementEnd
