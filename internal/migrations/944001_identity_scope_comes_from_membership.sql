-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 944001_identity_scope_comes_from_membership — звено цепи областей
-- `iam_user → account` берётся из ЧЛЕНСТВА, а не из колонки строки.
-- Стадия S3 (migrate) перехода IAM-ID-1, линия задачи kacho#471.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ НОМЕР ВЫВЕДЕН ИЗ #944, А НЕ ИЗ #471 — ИЗМЕРЕНО, А НЕ ВЫБРАНО
--
-- Соглашение `<задача><порядок>` (docs/architecture/migration-version-namespace.md)
-- требует номер задачи, а порядок применения — числовой. Задача #471 старше
-- всего, что уже применено (наибольший занятый номер — 893002), поэтому файл
-- `471001_*` встал бы в цепь ПЕРЕД `740001`, которая заводит это самое
-- представление глаголом `CREATE VIEW`. Проверено прогоном, а не рассуждением:
-- на чистой базе цепь падает с `relation "resource_scope_edge" already exists`
-- (SQLSTATE 42P07) — то есть сервис не поднимается вовсе.
--
-- Документ соглашения называет цену этого класса («миграция с меньшим номером
-- будет отвергнута мигратором — громко, на выкатке»), но описывает её для
-- ДОЛГОЖИВУЩЕЙ базы. Здесь отказ приходит на ЧИСТОЙ, и приходит раньше: не
-- «пропущенная миграция», а столкновение с объектом, которого на момент
-- применения ещё не должно существовать. Разбор и предмет — kacho#945.
--
-- Поэтому у этой работы своя задача (#944) со своим предикатом снятия, и номер
-- выведен из неё. Соглашение соблюдено дословно: номер выведен из задачи, чью
-- работу миграция и несёт.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ
--
-- Вопрос «через какой аккаунт администратор достаёт до личности» решается цепью
-- областей: `iam_user.super_admin: admin from account` ищет `admin` на предке
-- типа `account`, а предка называет представление `kacho_iam.resource_scope_edge`.
-- Его ветвь (4a) выводила предка из `kacho_iam.users.account_id` — то есть из
-- колонки, которую переход снимает.
--
-- Снятие колонки при живой ветви (4a) даёт отказ РАНТАЙМНЫЙ И ТИХИЙ: цепь
-- перестаёт находить предка, каскад отвечает «нет» там, где обязан отвечать
-- «да», и со стороны это неотличимо от честного отказа. Сборка об этом не знает
-- — источник лежит строкой SQL. Поэтому читатель переводится ЗАРАНЕЕ, отдельным
-- изменением, а не вместе со снятием колонки.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧТО ЭТА МИГРАЦИЯ ДЕЛАЕТ И ЧЕГО НЕ ДЕЛАЕТ
--
-- Делает: пересоздаёт представление, заменив ИСТОЧНИК одной ветви. Остальные
-- восемь ветвей воспроизведены ДОСЛОВНО — представление пересоздаётся целиком
-- (`CREATE OR REPLACE VIEW` не умеет менять одну ветвь), и любая правка соседней
-- ветви здесь была бы правкой чужого предмета.
--
-- НЕ делает: не трогает колонку, не трогает план чтения материализации
-- (`iamDirectScanSpecs`), не меняет модель прав и не заводит ни одного нового
-- отношения. Ни один субъект не получает доступа, которого у него не было.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ДЕЛТА ПУСТА — ПРОВЕРЯЕТСЯ ЗДЕСЬ, А НЕ ОБЪЯВЛЯЕТСЯ
--
-- Пока у каждого человека РОВНО ОДНО членство, колонка и таблица членств
-- называют одну и ту же пару: обратное заполнение и зеркалящий триггер 470001
-- держат их в согласии by construction. Значит правка не меняет ничьего доступа
-- — и это положительный контроль шага, а не признак его завершённости.
--
-- Утверждение о согласии ПРОВЕРЯЕТСЯ ниже сравнением двух множеств пар и роняет
-- миграцию на расхождении: заявление, которого никто не проверяет, перестаёт
-- быть верным молча. Печатается объём осмотренного — «ноль расхождений» обязано
-- быть отличимо от «ноль прочитанного».
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧТО СТАНОВИТСЯ ВОЗМОЖНЫМ — И ПОЧЕМУ ЭТО НАЗВАНО, А НЕ УМОЛЧАНО
--
-- Колонка одна на строку, поэтому ветвь (4a) давала личности РОВНО ОДНОГО
-- предка-аккаунт. Членств у человека может быть несколько, и тогда предков
-- становится несколько — то есть администратор ЛЮБОГО из аккаунтов достанет до
-- объекта личности.
--
-- Сегодня это состояние НЕ КОНСТРУИРУЕМО: второе членство заводит только глагол,
-- который на ресурс членства ещё не переехал, а зеркало держит ровно одну строку
-- на человека (`DELETE … WHERE account_id <> NEW.account_id`). Но переезд
-- глагола делает его конструируемым в тот же день — и вместе с ним обязана
-- приземлиться СМЕНА ОБЪЕКТА, про который спрашивает гейт: аккаунт-скоупным
-- объектом становится ЧЛЕНСТВО, а не личность (приёмка §2.3а).
--
-- Здесь это записано затем, чтобы порядок держался предметом, а не памятью:
-- ветвь ниже — не «пока сойдёт», а половина работы, вторая половина которой
-- названа и имеет предикат (тип `iam_membership` в модели прав).

-- +goose Up

CREATE OR REPLACE VIEW kacho_iam.resource_scope_edge AS
  -- (1) То, что прислал владелец объекта. Дословно, без отбора: чей ресурс — того
  --     и цепь. Не изменилось.
  SELECT e.object_type, e.object_id, e.parent_type, e.parent_id, e.depth
    FROM kacho_iam.resource_parent_edge e
UNION ALL
  -- (2) Предок ПРОЕКТА — из ПРОЕКЦИИ ЖУРНАЛА (781001). Не изменилось.
  SELECT 'project'::text,
         f.object_id,
         split_part(f.subject, ':', 1),
         substr(f.subject, position(':' in f.subject) + 1),
         1
    FROM kacho_iam.relation_fact f
   WHERE f.object_type = 'project'
     AND f.relation = split_part(f.subject, ':', 1)
     AND position('#' in f.subject) = 0
     AND NOT EXISTS (
           SELECT 1 FROM kacho_iam.resource_parent_edge e
            WHERE e.object_type = 'project' AND e.object_id = f.object_id)
UNION ALL
  -- (3) Предок АККАУНТА — кластер, из схемы (740001). Не изменилось.
  SELECT 'account'::text, a.id, 'cluster'::text, c.id, 1
    FROM kacho_iam.accounts a
   CROSS JOIN kacho_iam.clusters c
   WHERE NOT EXISTS (
           SELECT 1 FROM kacho_iam.resource_parent_edge e
            WHERE e.object_type = 'account' AND e.object_id = a.id)
UNION ALL
  -- (4a) ЛИЧНОСТЬ → аккаунт. Источник — kacho_iam.memberships (#471), а не
  --      колонка строки: принадлежность аккаунту перестала быть свойством
  --      строки человека и стала отдельной связью, которых у него может быть
  --      несколько.
  --
  --      Полнота по построению держится ТЕМ ЖЕ доводом, что у прочих ветвей
  --      этого блока: строка И ЕСТЬ связь — `memberships.id` первичный ключ, а
  --      пара `(user_id, account_id)` уникальна (470001), поэтому обойти строку
  --      и получить членство нельзя ни через API, ни через посев, ни через
  --      миграцию. Отличие от колонки одно: строк на человека бывает больше
  --      одной, и тогда звеньев у объекта столько же — что и есть предмет
  --      перехода.
  --
  --      Состояние членства НЕ ЧИТАЕТСЯ, и это то же решение, что у привязки в
  --      ветви (6): звено — указатель ВВЕРХ, а не выдача. Приглашённый человек
  --      обязан быть достижим администратору аккаунта, куда его пригласили, —
  --      иначе приглашение нельзя ни прочитать, ни отозвать ровно до первого
  --      входа приглашённого. Прежняя ветвь состояния тоже не читала.
  SELECT 'iam_user'::text, m.user_id, 'account'::text, m.account_id, 1
    FROM kacho_iam.memberships m
   WHERE COALESCE(m.account_id, '') <> ''
     AND NOT EXISTS (
           SELECT 1 FROM kacho_iam.resource_parent_edge e
            WHERE e.object_type = 'iam_user' AND e.object_id = m.user_id)
UNION ALL
  -- (4b) ГРУППА → аккаунт. Источник — kacho_iam.groups.account_id.
  SELECT 'iam_group'::text, o.id, 'account'::text, o.account_id, 1
    FROM kacho_iam.groups o
   WHERE COALESCE(o.account_id, '') <> ''
     AND NOT EXISTS (
           SELECT 1 FROM kacho_iam.resource_parent_edge e
            WHERE e.object_type = 'iam_group' AND e.object_id = o.id)
UNION ALL
  -- (4c) СЛУЖЕБНАЯ УЧЁТКА → аккаунт. Источник —
  --      kacho_iam.service_accounts.account_id. Проектной колонки у неё нет
  --      вовсе — она снята вместе с полем контракта, писателя у неё не было.
  SELECT 'iam_service_account'::text, o.id, 'account'::text, o.account_id, 1
    FROM kacho_iam.service_accounts o
   WHERE COALESCE(o.account_id, '') <> ''
     AND NOT EXISTS (
           SELECT 1 FROM kacho_iam.resource_parent_edge e
            WHERE e.object_type = 'iam_service_account' AND e.object_id = o.id)
UNION ALL
  -- (5a) РОЛЬ АККАУНТА → аккаунт. Источник — kacho_iam.roles.account_id.
  SELECT 'iam_role'::text, o.id, 'account'::text, o.account_id, 1
    FROM kacho_iam.roles o
   WHERE COALESCE(o.account_id, '') <> ''
     AND NOT EXISTS (
           SELECT 1 FROM kacho_iam.resource_parent_edge e
            WHERE e.object_type = 'iam_role' AND e.object_id = o.id)
UNION ALL
  -- (5b) РОЛЬ ПРОЕКТА → проект. Источник — kacho_iam.roles.project_id.
  SELECT 'iam_role'::text, o.id, 'project'::text, o.project_id, 1
    FROM kacho_iam.roles o
   WHERE COALESCE(o.project_id, '') <> ''
     AND NOT EXISTS (
           SELECT 1 FROM kacho_iam.resource_parent_edge e
            WHERE e.object_type = 'iam_role' AND e.object_id = o.id)
UNION ALL
  -- (6) ПРИВЯЗКА → её область. Источник — пара колонок
  --     kacho_iam.access_bindings.resource_type/resource_id, и ТОЛЬКО для трёх
  --     областных значений закрытого набора isBindableScope.
  SELECT 'iam_access_binding'::text, o.id, lower(o.resource_type), o.resource_id, 1
    FROM kacho_iam.access_bindings o
   WHERE lower(o.resource_type) IN ('project', 'account', 'cluster')
     AND COALESCE(o.resource_id, '') <> ''
     AND NOT EXISTS (
           SELECT 1 FROM kacho_iam.resource_parent_edge e
            WHERE e.object_type = 'iam_access_binding' AND e.object_id = o.id);

COMMENT ON VIEW kacho_iam.resource_scope_edge IS
  'Цепь областей, какой её читает вопрос о доступе: рёбра, присланные владельцами ресурсов (resource_parent_edge), ПЛЮС достроенные звенья. Предок ПРОЕКТА берётся из проекции журнала (relation_fact), предок АККАУНТА — из схемы (accounts × clusters). Предок ЛИЧНОСТИ — из kacho_iam.memberships (#471): принадлежность аккаунту перестала быть колонкой строки человека и стала отдельной связью, которых у него может быть несколько; состояние членства не читается — звено есть указатель вверх, а не выдача. Предок ГРУППЫ, СЛУЖЕБНОЙ УЧЁТКИ и РОЛИ — колонкой их собственной строки; предок ПРИВЯЗКИ — парой resource_type/resource_id для трёх областных значений закрытого набора isBindableScope. Правило одно: источник, полный ПО ПОСТРОЕНИЮ для ЭТОГО звена. Владелец, назвавший цепь своего объекта сам, вывод отменяет (NOT EXISTS). ПИСАТЬ СЮДА НЕЛЬЗЯ: производители пишут в resource_parent_edge и в журнал.';

-- ─────────────────────────────────────────────────────────────────────────────
-- Согласие двух источников на МОМЕНТ ПРИМЕНЕНИЯ: множество пар, которое давала
-- колонка, обязано совпасть с тем, которое даёт таблица членств. Расхождение
-- означает, что зеркало 470001 не держит их в согласии, — и тогда переводить
-- читателя нельзя, потому что делта не пуста.
-- +goose StatementBegin
DO $$
DECLARE
    n_column   bigint;
    n_member   bigint;
    n_only_col bigint;
    n_only_mem bigint;
BEGIN
    SELECT count(*) INTO n_column
      FROM kacho_iam.users u
     WHERE COALESCE(u.account_id, '') <> '';

    SELECT count(*) INTO n_member
      FROM kacho_iam.memberships m
     WHERE COALESCE(m.account_id, '') <> '';

    SELECT count(*) INTO n_only_col FROM (
        SELECT u.id AS uid, u.account_id AS aid FROM kacho_iam.users u
         WHERE COALESCE(u.account_id, '') <> ''
        EXCEPT
        SELECT m.user_id, m.account_id FROM kacho_iam.memberships m
    ) s;

    SELECT count(*) INTO n_only_mem FROM (
        SELECT m.user_id AS uid, m.account_id AS aid FROM kacho_iam.memberships m
         WHERE COALESCE(m.account_id, '') <> ''
        EXCEPT
        SELECT u.id, u.account_id FROM kacho_iam.users u
    ) s;

    RAISE NOTICE '471001 согласие источников звена: пар по колонке %, пар по членствам %, '
                 'только у колонки %, только у членств %',
                 n_column, n_member, n_only_col, n_only_mem;

    IF n_only_col <> 0 THEN
        RAISE EXCEPTION
            '471001: колонка называет % пар, которых нет в членствах — зеркало 470001 '
            'не держит источники в согласии, и перевод читателя ОТНЯЛ БЫ доступ',
            n_only_col;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down

CREATE OR REPLACE VIEW kacho_iam.resource_scope_edge AS
  SELECT e.object_type, e.object_id, e.parent_type, e.parent_id, e.depth
    FROM kacho_iam.resource_parent_edge e
UNION ALL
  SELECT 'project'::text,
         f.object_id,
         split_part(f.subject, ':', 1),
         substr(f.subject, position(':' in f.subject) + 1),
         1
    FROM kacho_iam.relation_fact f
   WHERE f.object_type = 'project'
     AND f.relation = split_part(f.subject, ':', 1)
     AND position('#' in f.subject) = 0
     AND NOT EXISTS (
           SELECT 1 FROM kacho_iam.resource_parent_edge e
            WHERE e.object_type = 'project' AND e.object_id = f.object_id)
UNION ALL
  SELECT 'account'::text, a.id, 'cluster'::text, c.id, 1
    FROM kacho_iam.accounts a
   CROSS JOIN kacho_iam.clusters c
   WHERE NOT EXISTS (
           SELECT 1 FROM kacho_iam.resource_parent_edge e
            WHERE e.object_type = 'account' AND e.object_id = a.id)
UNION ALL
  SELECT 'iam_user'::text, o.id, 'account'::text, o.account_id, 1
    FROM kacho_iam.users o
   WHERE COALESCE(o.account_id, '') <> ''
     AND NOT EXISTS (
           SELECT 1 FROM kacho_iam.resource_parent_edge e
            WHERE e.object_type = 'iam_user' AND e.object_id = o.id)
UNION ALL
  SELECT 'iam_group'::text, o.id, 'account'::text, o.account_id, 1
    FROM kacho_iam.groups o
   WHERE COALESCE(o.account_id, '') <> ''
     AND NOT EXISTS (
           SELECT 1 FROM kacho_iam.resource_parent_edge e
            WHERE e.object_type = 'iam_group' AND e.object_id = o.id)
UNION ALL
  SELECT 'iam_service_account'::text, o.id, 'account'::text, o.account_id, 1
    FROM kacho_iam.service_accounts o
   WHERE COALESCE(o.account_id, '') <> ''
     AND NOT EXISTS (
           SELECT 1 FROM kacho_iam.resource_parent_edge e
            WHERE e.object_type = 'iam_service_account' AND e.object_id = o.id)
UNION ALL
  SELECT 'iam_role'::text, o.id, 'account'::text, o.account_id, 1
    FROM kacho_iam.roles o
   WHERE COALESCE(o.account_id, '') <> ''
     AND NOT EXISTS (
           SELECT 1 FROM kacho_iam.resource_parent_edge e
            WHERE e.object_type = 'iam_role' AND e.object_id = o.id)
UNION ALL
  SELECT 'iam_role'::text, o.id, 'project'::text, o.project_id, 1
    FROM kacho_iam.roles o
   WHERE COALESCE(o.project_id, '') <> ''
     AND NOT EXISTS (
           SELECT 1 FROM kacho_iam.resource_parent_edge e
            WHERE e.object_type = 'iam_role' AND e.object_id = o.id)
UNION ALL
  SELECT 'iam_access_binding'::text, o.id, lower(o.resource_type), o.resource_id, 1
    FROM kacho_iam.access_bindings o
   WHERE lower(o.resource_type) IN ('project', 'account', 'cluster')
     AND COALESCE(o.resource_id, '') <> ''
     AND NOT EXISTS (
           SELECT 1 FROM kacho_iam.resource_parent_edge e
            WHERE e.object_type = 'iam_access_binding' AND e.object_id = o.id);

COMMENT ON VIEW kacho_iam.resource_scope_edge IS
  'Цепь областей, какой её читает вопрос о доступе: рёбра, присланные владельцами ресурсов (resource_parent_edge), ПЛЮС достроенные звенья. Предок ПРОЕКТА берётся из проекции журнала (relation_fact, отношение называет тип субъекта) — оттуда же, откуда его берёт движок отношений (#781). Предок АККАУНТА — из схемы (accounts × clusters): аккаунты сеются миграциями без указателя в журнале (#740). Предок ПЯТИ СОБСТВЕННЫХ ТИПОВ iam — из СХЕМЫ, колонкой собственной строки (#785): users/groups/service_accounts/roles.account_id, roles.project_id для проектной роли (взаимоисключающе по roles_definition_tier_xor), access_bindings.resource_type/resource_id для трёх областных значений закрытого набора isBindableScope. Правило одно: источник, полный ПО ПОСТРОЕНИЮ для ЭТОГО звена. У пяти типов полна схема — строка И ЕСТЬ объект, указатель лежит её колонкой и неизменяем, а журнал наблюдаемо неполон: девять миграций сеют эти строки и ни одна не пишет указатель. Владелец, назвавший цепь своего объекта сам, вывод отменяет (NOT EXISTS) — ветви взаимоисключающи, двух мест об одном предмете нет. Каждая ветвь даёт объекту РОВНО ОДНО звено; максимум по дереву 2 при пределе обхода 4, и это проверяется переписью, а не выводится. ПИСАТЬ СЮДА НЕЛЬЗЯ: производители пишут в resource_parent_edge и в журнал.';
