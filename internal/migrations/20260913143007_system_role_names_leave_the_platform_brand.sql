-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- system_role_names_leave_the_platform_brand — ИМЕНА двух встроенных ролей
-- перестают называть платформу: `kacho-system.admin` → `system.admin`,
-- `kacho-system.viewer` → `system.viewer`.
--
-- Задача продукта #2554, класс B APPROVED-приёмки
-- `docs/engineering/acceptance/seed-identity-names-its-own-service.md`
-- (§2.1 класс B, §2.3 написание, §8 шаг 2). Довод написания здесь не
-- пересказывается — он в §2.3: имя называет УСТАНОВКУ, а не продукт.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ЭТО НЕ ПЕРЕНОС ВЫДАЧИ, ХОТЯ ВЫГЛЯДИТ ПОХОЖЕ
--
-- Идентификаторы обеих ролей РУКОПИСНЫЕ (`rol000000000sysadmin`,
-- `rol000000000sysviewer`), а не выведенные из имени: свод называет их такими
-- своим комментарием. Значит перевод ИМЕНИ не двигает ни одной ссылки
-- `access_bindings.role_id`, и замок `TestNoMigrationMovesGrantsBetweenRoles`
-- остаётся зелёным by construction — здесь нет ни одного оператора, который
-- переставлял бы `role_id`.
--
-- Строка адресуется ИДЕНТИФИКАТОРОМ, а не именем: имя — ровно то, что мы
-- двигаем, и искать по нему значило бы искать по величине, о которой спор.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧЕГО ЭТА МИГРАЦИЯ НЕ ДЕЛАЕТ — НАЗВАНО, ЧТОБЫ НЕ ИСКАЛИ
--
--   * ПРИЗНАК СИСТЕМНОСТИ не трогает. `roles_custom_name_check` допускает точку
--     в имени только первым дизъюнктом `is_system`; снять признак значило бы
--     сделать объявленное имя незаконным тем же изменением, которое его вводит.
--     Признак проверяется пробой, а не предполагается;
--   * ПРАВА и ПРАВИЛА строки не трогает. Их содержимое — предмет миграции
--     `20260905040500`, и повторно решать его здесь нечего;
--   * ОКНА в базе не требует. `roles_system_unique` глобален в пределах
--     кластера: двух строк с двумя написаниями не бывает by construction.
--     Окно живёт у ЧИТАТЕЛЯ имени (`domain.SeedIdentityWindow`,
--     `PermissionRegistry.PermissionsForRole`) и приезжает тем же изменением.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ТРИ ИСХОДА НА КАЖДУЮ РОЛЬ, И ТРЕТИЙ — ОТКАЗ, А НЕ ТИШИНА
--
--   * имя прежнее         → переписывается;
--   * имя уже объявленное → делать нечего, проход молча (установка, поднятая
--                           после перехода);
--   * имя ТРЕТЬЕ          → ОТКАЗ. Встроенную роль оператор переименовать не
--                           должен, но если имя всё же иное — мы не знаем, чьё
--                           оно и почему, а затирать молча значит уничтожать
--                           след чужого решения.

-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE
    v_role     record;
    v_now      text;
    v_rows     bigint;
BEGIN
    FOR v_role IN
        SELECT * FROM (VALUES
            ('rol000000000sysadmin',  'kacho-system.admin',  'system.admin'),
            ('rol000000000sysviewer', 'kacho-system.viewer', 'system.viewer')
        ) AS t(id, previous, declared)
    LOOP
        SELECT name INTO v_now FROM kaname.roles WHERE id = v_role.id;

        IF NOT FOUND THEN
            RAISE EXCEPTION
                'встроенной роли % в таблице нет: её сеет свод, и её отсутствие означает, что цепочка говорит не о том дереве. Молчаливый проход выдал бы это за сделанную работу.',
                v_role.id;
        END IF;

        IF v_now = v_role.declared THEN
            RAISE NOTICE 'имя роли % уже %: переписывать нечего.', v_role.id, v_role.declared;
            CONTINUE;
        END IF;

        IF v_now <> v_role.previous THEN
            RAISE EXCEPTION
                'имя роли % — %, а переход объявлен с % на %. Чьё это имя и почему, миграция не знает; затирать его молча нельзя. Разберите расхождение до применения свода.',
                v_role.id, v_now, v_role.previous, v_role.declared;
        END IF;

        UPDATE kaname.roles SET name = v_role.declared WHERE id = v_role.id;
        GET DIAGNOSTICS v_rows = ROW_COUNT;

        IF v_rows <> 1 THEN
            RAISE EXCEPTION
                'перевод имени роли % затронул строк %, ожидалась одна.', v_role.id, v_rows;
        END IF;

        RAISE NOTICE 'имя роли % переписано % → %.', v_role.id, v_role.previous, v_role.declared;
    END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
DECLARE
    v_role record;
BEGIN
    -- Обратный ход возвращает ИМЕННО то, что завёл прямой, и только если оно на
    -- месте: строка с третьим написанием обратным ходом не трогается — иначе
    -- откат уничтожил бы чужой след так же молча, как затирание.
    FOR v_role IN
        SELECT * FROM (VALUES
            ('rol000000000sysadmin',  'kacho-system.admin',  'system.admin'),
            ('rol000000000sysviewer', 'kacho-system.viewer', 'system.viewer')
        ) AS t(id, previous, declared)
    LOOP
        UPDATE kaname.roles
           SET name = v_role.previous
         WHERE id = v_role.id AND name = v_role.declared;
    END LOOP;
END $$;
-- +goose StatementEnd
