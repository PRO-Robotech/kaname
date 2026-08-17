-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 0101_system_role_rules_speak_the_catalog_dictionary — правила доменных
-- системных ролей называют ресурс так, как его называет каталог типов.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ
--
-- Правила системных ролей адресуют объект парой `<модуль>.<ресурс>`, и эта пара
-- обязана резолвиться закрытым каталогом типов (`authzmap.FGAObjectType`).
-- Четыре семейства называли ресурс в ЗМЕИНОМ написании, тогда как каталог несёт
-- ВЕРБЛЮЖЬЕ:
--
--     правила посева          каталог типов
--     iam.service_account     iam.serviceAccount
--     iam.access_binding      iam.accessBinding
--     vpc.security_group      vpc.securityGroup
--     vpc.route_table         vpc.routeTable
--
-- Селектор, чей тип не резолвится, инертен ЦЕЛИКОМ: по нему не находит объекта
-- ни материализатор кортежей, ни проекция глаголов, ни обнаружение привязок.
-- Двенадцать доменных ролей не давали НИ ОДНОГО пообъектного права.
--
-- И не давали молча — вот почему это дефект, а не косметика. Ярусный кортеж на
-- якоре области кладёт ЛЕГАСИ-ветка эмиссии, то есть роль БЕЗ правил; у всех
-- двенадцати правила ЕСТЬ, поэтому эмиссия идёт правиловой веткой и кладёт
-- только иерархический указатель. Ни пообъектной выдачи, ни ярусной: тенант,
-- которому выдали `vpc.route_table.view`, не получал ничего, а привязка
-- создавалась, читалась и выглядела действующей. Пустое соединение неотличимо
-- от честного «права нет».
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ИМЕНА, А НЕ ПРАВИЛА
--
-- Путей закрытия было два, и они дают РАЗНОЕ. Привести имена к словарю — роли
-- начинают работать так, как их задумывали. Снять правила — роль уходит в
-- легаси-ветку и выдаёт ЯРУС на якоре области: это не уборка, а другая выдача,
-- шире задуманной, и она потребовала бы своей приёмки. Выбран первый.
--
-- ПРАВА ПЕРЕИМЕНОВЫВАЮТСЯ ВМЕСТЕ С ПРАВИЛАМИ, и это не побочная правка. Ярус,
-- выведенный из правил, обязан совпадать с ярусом, выведенным из строк прав
-- (tier-parity, проба `TestSeededRoleTierParity`), а совпадение это держится
-- тем, что правила повторяют строки прав ДОСЛОВНО. Переименовать одну сторону
-- значит развести ключи `<модуль>.<ресурс>` двух проекций и получить красное
-- там, где всё верно. Грамматика прав camelCase допускает — сегмент ресурса
-- объявлен как `[a-z][a-zA-Z0-9_-]*` (валидатор миграции 0005).
--
-- ИМЯ И ИДЕНТИФИКАТОР РОЛИ НЕ МЕНЯЮТСЯ. `id` выведен из имени (`md5`), имя
-- тенант-видимо и стоит в уже выданных привязках; менять его значило бы
-- завести НОВЫЕ роли и осиротить выдачи. Написание имени роли ни с чем не
-- соединяется — резолвится только пара из правил.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ОТДЕЛЬНЫЙ СЛУЧАЙ: loadbalancer.operations
--
-- Здесь оба пути выше неприменимы: типа с таким именем в каталоге НЕТ и быть не
-- должно. Операция — не объект выдачи; доступ к ней решается на её
-- ресурсе-владельце (балансировщик, слушатель, группа целей), и все три у этих
-- ролей уже названы своими правилами. Поэтому правило и зеркалящая его строка
-- прав снимаются с обеих ролей балансировщика. Функционально это не отнимает
-- ничего: правило не материализовало ни одного кортежа за всё время жизни.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ НЕ НУЖЕН ПЕРЕСЕВ СЕЛЕКТОРОВ
--
-- `role_rule_selectors` не правится здесь ни одной строкой, и это не упущение.
-- Отпечаток правила (`Rule.Fingerprint`) считается по его содержимому, поэтому
-- переименование ресурса меняет отпечаток: досев на старте (`syncAllSystemRole-
-- SelectorsTx`) снимает строку со старым отпечатком как отсутствующую в текущем
-- наборе, кладёт новую и полностью переписывает проекцию глаголов. Писать сюда
-- ещё и данные значило бы завести второе место, знающее соответствие.
--
-- Проверяется: TestSystemRoleVerbProjectionIsSeededAlongsideItsSelectors
-- (нерезолвящихся селекторов ноль), TestSeededRoleRulesResolveOrArePinned,
-- TestSeededRoleTierParity. Заведено: PRO-Robotech/kacho#513.

-- +goose Up

-- 1. Четыре семейства: ресурс в правилах и в правах приводится к словарю
--    каталога. Замена идёт по ТОКЕНУ, а не по целому значению, поэтому она не
--    зависит от того, что ещё успело измениться в этих ролях после посева.
UPDATE kacho_iam.roles
SET rules = replace(rules::text, '"service_account"', '"serviceAccount"')::jsonb,
    permissions = (
        SELECT jsonb_agg(replace(p, 'iam.service_account.', 'iam.serviceAccount.'))
        FROM jsonb_array_elements_text(permissions) p)
WHERE is_system AND name LIKE 'iam.service_account.%';

UPDATE kacho_iam.roles
SET rules = replace(rules::text, '"access_binding"', '"accessBinding"')::jsonb,
    permissions = (
        SELECT jsonb_agg(replace(p, 'iam.access_binding.', 'iam.accessBinding.'))
        FROM jsonb_array_elements_text(permissions) p)
WHERE is_system AND name LIKE 'iam.access_binding.%';

UPDATE kacho_iam.roles
SET rules = replace(rules::text, '"security_group"', '"securityGroup"')::jsonb,
    permissions = (
        SELECT jsonb_agg(replace(p, 'vpc.security_group.', 'vpc.securityGroup.'))
        FROM jsonb_array_elements_text(permissions) p)
WHERE is_system AND name LIKE 'vpc.security_group.%';

UPDATE kacho_iam.roles
SET rules = replace(rules::text, '"route_table"', '"routeTable"')::jsonb,
    permissions = (
        SELECT jsonb_agg(replace(p, 'vpc.route_table.', 'vpc.routeTable.'))
        FROM jsonb_array_elements_text(permissions) p)
WHERE is_system AND name LIKE 'vpc.route_table.%';

-- 2. Операции — не объект выдачи: правило и зеркалящая его строка прав снимаются.
UPDATE kacho_iam.roles
SET rules = COALESCE((
        SELECT jsonb_agg(e)
        FROM jsonb_array_elements(rules) e
        WHERE NOT (e->'resources' ? 'operations')), '[]'::jsonb),
    permissions = COALESCE((
        SELECT jsonb_agg(p)
        FROM jsonb_array_elements_text(permissions) p
        WHERE p NOT LIKE 'loadbalancer.operations.%'), '[]'::jsonb)
WHERE is_system AND name IN ('loadbalancer.operator', 'loadbalancer.target_manager');

-- 3. Миграция проверяет СВОЙ исход и откатывается, если он не достигнут.
--    Без этого «ноль изменённых строк» (роль переименовали, посев не доехал,
--    условие промахнулось) было бы неотличимо от успеха: goose записал бы
--    версию, а дефект остался бы на месте.
-- +goose StatementBegin
DO $$
DECLARE
    stale text;
BEGIN
    SELECT string_agg(DISTINCT tok, ', ' ORDER BY tok) INTO stale
    FROM kacho_iam.roles r,
         LATERAL jsonb_array_elements(COALESCE(r.rules, '[]'::jsonb)) e,
         LATERAL jsonb_array_elements_text(COALESCE(e->'resources', '[]'::jsonb)) tok
    WHERE r.is_system
      AND tok IN ('service_account', 'access_binding', 'security_group', 'route_table', 'operations');

    IF stale IS NOT NULL THEN
        RAISE EXCEPTION
            'правила системных ролей всё ещё называют ресурс вне словаря каталога: % — '
            'селектор по такому имени инертен целиком (kacho#513)', stale;
    END IF;
END;
$$;
-- +goose StatementEnd

-- +goose Down

-- Возврат к змеиному написанию — вместе с правами, той же парой, что и выше:
-- разъехавшись, они дали бы красное на паритете ярусов. Правило операций
-- восстанавливается обеим ролям балансировщика.
UPDATE kacho_iam.roles
SET rules = replace(rules::text, '"serviceAccount"', '"service_account"')::jsonb,
    permissions = (
        SELECT jsonb_agg(replace(p, 'iam.serviceAccount.', 'iam.service_account.'))
        FROM jsonb_array_elements_text(permissions) p)
WHERE is_system AND name LIKE 'iam.service_account.%';

UPDATE kacho_iam.roles
SET rules = replace(rules::text, '"accessBinding"', '"access_binding"')::jsonb,
    permissions = (
        SELECT jsonb_agg(replace(p, 'iam.accessBinding.', 'iam.access_binding.'))
        FROM jsonb_array_elements_text(permissions) p)
WHERE is_system AND name LIKE 'iam.access_binding.%';

UPDATE kacho_iam.roles
SET rules = replace(rules::text, '"securityGroup"', '"security_group"')::jsonb,
    permissions = (
        SELECT jsonb_agg(replace(p, 'vpc.securityGroup.', 'vpc.security_group.'))
        FROM jsonb_array_elements_text(permissions) p)
WHERE is_system AND name LIKE 'vpc.security_group.%';

UPDATE kacho_iam.roles
SET rules = replace(rules::text, '"routeTable"', '"route_table"')::jsonb,
    permissions = (
        SELECT jsonb_agg(replace(p, 'vpc.routeTable.', 'vpc.route_table.'))
        FROM jsonb_array_elements_text(permissions) p)
WHERE is_system AND name LIKE 'vpc.route_table.%';

-- Модуль здесь СКАЛЯР, а не массив: форма `{"modules":[…]}` из посева 0031
-- приведена к скалярной миграцией 0033, и массивная форма отвергается CHECK
-- `roles_rules_valid` (SQLSTATE 23514). Первая редакция этого отката вернула
-- массив и была поймана round-trip-пробами миграций — тем самым, ради чего они
-- и написаны: откат исполняется редко, и его ошибка иначе ждала бы того дня,
-- когда он понадобится.
UPDATE kacho_iam.roles
SET rules = rules || '[{"module":"loadbalancer","resources":["operations"],"verbs":["get"]}]'::jsonb,
    permissions = permissions || '["loadbalancer.operations.*.get"]'::jsonb
WHERE is_system AND name IN ('loadbalancer.operator', 'loadbalancer.target_manager');
