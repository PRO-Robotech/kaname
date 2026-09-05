-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- system_roles_drop_the_read_action — строки прав системных ролей перестают
-- называть действие, которого каталог прав не несёт.
--
-- Задача продукта #1827.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧТО НЕВЕРНО СЕГОДНЯ
--
-- Шестнадцать системных ролей несут строку прав вида `<модуль>.<ресурс>.*.read`
-- (у двух глобальных — `*.*.*.read`). Действия `read` среди действий каталога
-- прав НЕТ: замер по встроенной копии каталога — 350 записей, 90 различных
-- действий, `read` среди них отсутствует.
--
-- Край резолвит действие в отношение ПО КАТАЛОГУ, поэтому право, названное этой
-- строкой, на пути запроса не спрашивается никогда. Оно действует — но не потому,
-- что названо, а потому, что рядом в той же роли стоят `list` и `get`, у которых
-- записи каталога есть. Роль, где `read` остался бы единственным действием, не
-- дала бы ничего, а её имя обещало бы чтение. Это «принято-и-проигнорировано»
-- (`api-conventions.md`) на уровне посева.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ИСХОД — СНЯТИЕ, а не объявление действия каталогом
--
-- Исходов у задачи три, и «оставить как есть» среди них нет (ban #11):
-- привести к каноническому действию · объявить действие каталогом прав · снять
-- как никогда не действовавшее.
--
-- Приводить не к чему: канонические действия чтения — `list` и `get`, и ОБА уже
-- стоят в каждой из шестнадцати ролей рядом со снимаемым. Приведение дало бы
-- дубль, а не право.
--
-- Объявлять каталогом — значит завести запись каталога без RPC: у действия `read`
-- нет ни одного глагола, который его производит, и запись стала бы обещанием,
-- за которое никто не отвечает.
--
-- Остаётся снятие. Оно НИЧЕГО НЕ ОТНИМАЕТ, и это измерено, а не предположено:
-- каждая из шестнадцати ролей несёт `list` и `get` на ТОЙ ЖЕ паре
-- «модуль.ресурс», а классификатор глагола (`authzmap.verbClass`,
-- `legacyVerbTier`) относит `read`, `list` и `get` к ОДНОМУ ярусу — `viewer`.
-- Множество отношений, в которое разворачивается роль, после снятия то же самое.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ФОРМА — ЛИТЕРАЛЬНЫЙ массив, а не выражение над jsonb
--
-- Массив прав присваивается целиком литералом намеренно. Свод цепочки должен
-- быть вычислим ЧТЕНИЕМ: гейт
-- `TestSystemRolePermissionActionExistsInTheCatalog` складывает присвоения по
-- порядку применения и судит последнее, а выражение над jsonb пришлось бы
-- исполнять — то есть гейт стал бы интеграционным и не исполнялся бы в коротком
-- прогоне, там, где строки прав и правят.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧТО МЕНЯЕТСЯ НАБЛЮДАЕМО
--
-- Ровно одно: перечень прав шестнадцати системных ролей становится короче на
-- одну строку каждая. Ни одно отношение не снимается, ни одна выдача не
-- отзывается, ярус каждой пары «модуль.ресурс» остаётся прежним.

-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
    IF to_regclass('kacho_iam.roles') IS NULL THEN
        RAISE EXCEPTION 'kacho_iam.roles не существует — цепочка миграций применена не с начала';
    END IF;
END
$$;
-- +goose StatementEnd

-- kacho-system.viewer
UPDATE kacho_iam.roles SET permissions = '["*.*.*.list", "*.*.*.get"]'::jsonb WHERE id = 'rol000000000sysviewer';
-- view
UPDATE kacho_iam.roles SET permissions = '["*.*.*.list", "*.*.*.get"]'::jsonb WHERE id = 'rol1bda80f2be4d3658e';
-- vpc.address.view
UPDATE kacho_iam.roles SET permissions = '["vpc.address.*.list", "vpc.address.*.get"]'::jsonb WHERE id = 'rol096a471229217fbcf';
-- vpc.security_group.view
UPDATE kacho_iam.roles SET permissions = '["vpc.securityGroup.*.list", "vpc.securityGroup.*.get"]'::jsonb WHERE id = 'rol1469d1a633ceae4b5';
-- vpc.gateway.view
UPDATE kacho_iam.roles SET permissions = '["vpc.gateway.*.list", "vpc.gateway.*.get"]'::jsonb WHERE id = 'rol26a49318d88632af2';
-- vpc.subnet.view
UPDATE kacho_iam.roles SET permissions = '["vpc.subnet.*.list", "vpc.subnet.*.get"]'::jsonb WHERE id = 'rol31f5c2b4e7b3ee06c';
-- iam.account.view
UPDATE kacho_iam.roles SET permissions = '["iam.account.*.list", "iam.account.*.get"]'::jsonb WHERE id = 'rol41dd066874f699c17';
-- compute.instance.view
UPDATE kacho_iam.roles SET permissions = '["compute.instance.*.list", "compute.instance.*.get"]'::jsonb WHERE id = 'rol6be01c0948936754b';
-- iam.project.view
UPDATE kacho_iam.roles SET permissions = '["iam.project.*.list", "iam.project.*.get"]'::jsonb WHERE id = 'rol7ad445624b1d0e9a1';
-- vpc.route_table.view
UPDATE kacho_iam.roles SET permissions = '["vpc.routeTable.*.list", "vpc.routeTable.*.get"]'::jsonb WHERE id = 'rolab84e08ef4b5e0b22';
-- iam.access_binding.view
UPDATE kacho_iam.roles SET permissions = '["iam.accessBinding.*.list", "iam.accessBinding.*.get"]'::jsonb WHERE id = 'rolb18c533133af2f130';
-- iam.group.view
UPDATE kacho_iam.roles SET permissions = '["iam.group.*.list", "iam.group.*.get"]'::jsonb WHERE id = 'rolc98b067591ded99e5';
-- iam.user.view
UPDATE kacho_iam.roles SET permissions = '["iam.user.*.list", "iam.user.*.get"]'::jsonb WHERE id = 'role2f47108d41b38f39';
-- iam.role.view
UPDATE kacho_iam.roles SET permissions = '["iam.role.*.list", "iam.role.*.get"]'::jsonb WHERE id = 'rolee27bb5ba1efb68cb';
-- iam.service_account.view
UPDATE kacho_iam.roles SET permissions = '["iam.serviceAccount.*.list", "iam.serviceAccount.*.get"]'::jsonb WHERE id = 'rolfc25814dc6989172d';
-- vpc.network.view
UPDATE kacho_iam.roles SET permissions = '["vpc.network.*.list", "vpc.network.*.get"]'::jsonb WHERE id = 'rolfe683216e63311d3f';

-- +goose Down
-- +goose StatementBegin
-- Откат возвращает строки прав дословно такими, какими их посеяла базовая
-- миграция, — включая снятое действие. Иначе он не откат.
UPDATE kacho_iam.roles SET permissions = '["*.*.*.read", "*.*.*.list", "*.*.*.get"]'::jsonb WHERE id = 'rol000000000sysviewer';
UPDATE kacho_iam.roles SET permissions = '["*.*.*.read", "*.*.*.list", "*.*.*.get"]'::jsonb WHERE id = 'rol1bda80f2be4d3658e';
UPDATE kacho_iam.roles SET permissions = '["vpc.address.*.read", "vpc.address.*.list", "vpc.address.*.get"]'::jsonb WHERE id = 'rol096a471229217fbcf';
UPDATE kacho_iam.roles SET permissions = '["vpc.securityGroup.*.read", "vpc.securityGroup.*.list", "vpc.securityGroup.*.get"]'::jsonb WHERE id = 'rol1469d1a633ceae4b5';
UPDATE kacho_iam.roles SET permissions = '["vpc.gateway.*.read", "vpc.gateway.*.list", "vpc.gateway.*.get"]'::jsonb WHERE id = 'rol26a49318d88632af2';
UPDATE kacho_iam.roles SET permissions = '["vpc.subnet.*.read", "vpc.subnet.*.list", "vpc.subnet.*.get"]'::jsonb WHERE id = 'rol31f5c2b4e7b3ee06c';
UPDATE kacho_iam.roles SET permissions = '["iam.account.*.read", "iam.account.*.list", "iam.account.*.get"]'::jsonb WHERE id = 'rol41dd066874f699c17';
UPDATE kacho_iam.roles SET permissions = '["compute.instance.*.read", "compute.instance.*.list", "compute.instance.*.get"]'::jsonb WHERE id = 'rol6be01c0948936754b';
UPDATE kacho_iam.roles SET permissions = '["iam.project.*.read", "iam.project.*.list", "iam.project.*.get"]'::jsonb WHERE id = 'rol7ad445624b1d0e9a1';
UPDATE kacho_iam.roles SET permissions = '["vpc.routeTable.*.read", "vpc.routeTable.*.list", "vpc.routeTable.*.get"]'::jsonb WHERE id = 'rolab84e08ef4b5e0b22';
UPDATE kacho_iam.roles SET permissions = '["iam.accessBinding.*.read", "iam.accessBinding.*.list", "iam.accessBinding.*.get"]'::jsonb WHERE id = 'rolb18c533133af2f130';
UPDATE kacho_iam.roles SET permissions = '["iam.group.*.read", "iam.group.*.list", "iam.group.*.get"]'::jsonb WHERE id = 'rolc98b067591ded99e5';
UPDATE kacho_iam.roles SET permissions = '["iam.user.*.read", "iam.user.*.list", "iam.user.*.get"]'::jsonb WHERE id = 'role2f47108d41b38f39';
UPDATE kacho_iam.roles SET permissions = '["iam.role.*.read", "iam.role.*.list", "iam.role.*.get"]'::jsonb WHERE id = 'rolee27bb5ba1efb68cb';
UPDATE kacho_iam.roles SET permissions = '["iam.serviceAccount.*.read", "iam.serviceAccount.*.list", "iam.serviceAccount.*.get"]'::jsonb WHERE id = 'rolfc25814dc6989172d';
UPDATE kacho_iam.roles SET permissions = '["vpc.network.*.read", "vpc.network.*.list", "vpc.network.*.get"]'::jsonb WHERE id = 'rolfe683216e63311d3f';
-- +goose StatementEnd
