-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- 20260904135459_role_owner_module_needs_a_liveness_key — СНЯТИЕ МОДУЛЯ при
-- живых ролях: порядок держит КЛЮЧ, а не рассуждение.
--
-- Задача продукта #2026. Предмет назван APPROVED-приёмками с обеих сторон:
-- role-ownership-tier-apart-from-cluster-anchor.md (IAM-OM-1) §2.1 — врезка
-- «Что этот ключ НЕ держит»; role-withdrawal-has-a-producer.md (IAM-RW-1)
-- §9 Р1 — остаток с предикатом снятия; architecture/role-withdrawal-is-a-mark.md
-- §«Что это решение РАЗМЫКАЕТ» — довод, почему форма стала выразимой.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧТО НЕВЕРНО СЕГОДНЯ
--
-- Единственный ключ от `roles` к `catalog_module` идёт на ПЕРВИЧНЫЙ ключ
-- `(module)` — то есть на строку независимо от её живости. Поэтому состояние
-- «модуль СНЯТ, а его роли ЖИВЫ и грантуют» ПРЕДСТАВИМО, и отвергнуть его
-- нечем: ограничений `roles`, называющих `owner_module`, три, и все про другое —
-- `roles_owner_module_is_cluster_tier` (ярус), `roles_owner_module_name_prefix`
-- (имя), `roles_rule_wildcards_confined` (подстановка). Триггера нет.
--
-- Это ровно ban #10: инвариант внутри одной БД выражается конструкцией БД, а не
-- рассуждением о том, кто её читает.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ЭТА ФОРМА СТАЛА ВЫРАЗИМОЙ ТОЛЬКО СЕЙЧАС
--
-- Круг 1 приёмки IAM-OM-1 ту же пару ОТВЕРГ — и отверг ПРОГОНОМ, а не вкусом.
-- Составляющая вида `CASE WHEN owner_module IS NOT NULL THEN true END` даёт
-- константу `true`: строка отпускает референт только своим УДАЛЕНИЕМ, а удаления
-- у роли модуля нет ни одного (`role_repo.go` удаляет лишь `is_system = false`;
-- применитель объявляет роль системной безусловно; гейт `applierneverdeletes`
-- удаление применителю ЗАПРЕЩАЕТ). Модуль с ролью не снимался бы НИКОГДА — то
-- есть отрицательный сценарий зеленел бы ровно тем исходом, который
-- положительный контроль заведён отличать.
--
-- `#1913` дал роли ПОМЕТКУ снятия (`roles.live` под
-- `roles_live_matches_retired`, референт `roles_id_live_uk`), и недостающая
-- половина появилась: `CASE WHEN live THEN true END` обращается в `NULL` у
-- снятой строки, и снятая роль модуль ОТПУСКАЕТ. Производитель пометки в дереве
-- есть и провязан (`RetireRole` → `moduleroles/retire.go` → композиционный
-- корень `cmd/kacho-iam/module_roles_apply.go`), поэтому выход из состояния
-- существует не на бумаге.
--
-- Порядок держится в ОБЕ стороны, и обе половины проверены прогоном:
--
--   вниз   снять модуль, пока жива хоть одна его роль   → 23503
--   вниз   снять модуль, все роли которого сняты        → проходит
--   вверх  оживить роль при снятом модуле               → 23503
--   вверх  оживить модуль, затем его роли               → проходит
--
-- Половина «вверх» — не побочный эффект: без неё повторная установка модуля
-- упиралась бы в отказ, и причину искали бы в форме оживления строки, а не в
-- порядке.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ПРЕЖНИЙ КЛЮЧ ОСТАЁТСЯ РЯДОМ, А НЕ ЗАМЕНЯЕТСЯ
--
-- `roles_owner_module_fk` утверждает ДРУГОЕ — «владелец известен платформе» — и
-- утверждает это БЕЗУСЛОВНО. Ключ живости под `MATCH SIMPLE` у снятой строки не
-- проверяется вовсе, поэтому снятая им одним роль вправе назвать владельцем что
-- угодно. Тот же порядок стоит уровнем выше: у `catalog_resource` живут ОБА
-- ключа (`catalog_resource_module_fk` и `catalog_resource_module_live_fk`).
--
-- Сверх того на ИМЯ прежнего ключа ключуется сценарий `-10` APPROVED-приёмки
-- IAM-OM-1 и его проба (`role_ownership_tier_integration_test.go`): снятие
-- сделало бы красной чужую посаженную работу.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЦЕНА ФОРМЫ — НАЗВАНА, И ДОВОД СОСЕДА СЮДА НЕ ПЕРЕНОСИТСЯ
--
-- `ADD COLUMN … GENERATED ALWAYS AS … STORED` ПЕРЕПИСЫВАЕТ таблицу и берёт на
-- неё `ACCESS EXCLUSIVE`. Сосед (`20260902065414`) списал эту цену словами «на
-- каталоге из тридцати строк это ничто» — и сам же велел пересчитать её на
-- следующей таблице. Пересчитано:
--
--   * `roles` каталогом НЕ является и растёт с арендаторами (`roles_account_fk`,
--     `roles_project_fk`);
--   * но растёт она ОПРЕДЕЛЕНИЯМИ ролей, а не выдачами: выдачи живут в
--     `access_bindings` (`access_bindings_role_fk`), и эта таблица не трогается
--     ни одним оператором ниже. На свежей схеме `roles` несёт 48 строк;
--   * ПРЕЦЕДЕНТА «вычисляемую колонку уже добавляли к `roles`» НЕТ, и ссылаться
--     на `is_system` нельзя: она заведена ВМЕСТЕ с таблицей, а не поздней
--     миграцией. Перепись переписываемых строк печатается ниже — цена названа
--     числом на той базе, где миграция применяется, а не выписана здесь.
--
-- ПОЧЕМУ НЕ `NOT VALID` + `VALIDATE CONSTRAINT`, хотя IAM-OM-1 §2.1 пользуется
-- этой формой. Там она покупает реальное: `ADD COLUMN` пустой колонки —
-- метаданные, поэтому единственным проходом по таблице остаётся проверка ключа,
-- и её стоит увести под более слабую блокировку. Здесь таблица переписывается
-- ВСЁ РАВНО, а goose ведёт миграцию одной транзакцией — значит `ACCESS
-- EXCLUSIVE` удерживается до фиксации в любом случае, и расщепление не покупает
-- НИЧЕГО. Написать его тут значило бы заявить выигрыш, которого нет.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ОТВЕРГНУТЫЕ ФОРМЫ — с причиной, а не с предпочтением
--
--   `FOREIGN KEY (owner_module, live) → catalog_module (module, live)` — без
--   новой колонки. ОТВЕРГНУТА: снятая роль (`live = false`) потребовала бы
--   строки `(module, false)`, то есть СНЯТОГО модуля. А снятие одной роли при
--   живом модуле — штатный, самый частый случай: манифест перестал объявлять
--   одну свою роль. Форма запретила бы ровно его.
--
--   Триггер вместо ключа. ОТВЕРГНУТА: заводит второго писателя инварианта и
--   проверяет его позже, чем ключ, — тот же класс, что software check-then-act.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧЕГО ЭТА МИГРАЦИЯ НЕ ДАЁТ
--
-- Она не отменяет и не сужает `roles_owner_module_fk` (см. выше) и не трогает ни
-- одной строки: живость роли и живость модуля остаются ровно теми, какими были.
-- Она меняет ПРЕДСТАВИМОЕ, а не посеянное.

-- +goose Up

-- Перепись ДО — чтобы самопроверка ниже утверждала «эта миграция живости не
-- меняла» замером, а не выписанным числом. Выписанное число устарело бы молча:
-- ролей у арендаторов тем больше, чем дольше живёт кластер.
CREATE TEMP TABLE _roles_before ON COMMIT DROP AS
SELECT (SELECT count(*) FROM kaname.roles)                              AS roles_all,
       (SELECT count(*) FROM kaname.roles WHERE live)                   AS roles_live,
       (SELECT count(*) FROM kaname.roles WHERE owner_module IS NOT NULL) AS roles_owned,
       (SELECT count(*) FROM kaname.catalog_module WHERE live)          AS modules_live;

ALTER TABLE kaname.roles
  ADD COLUMN owner_module_live boolean
    GENERATED ALWAYS AS (CASE WHEN live THEN true END) STORED;

COMMENT ON COLUMN kaname.roles.owner_module_live IS
  'Составляющая ключа «мой модуль-владелец ЖИВ». У живой роли — true, у снятой — NULL, и NULL здесь означает «эта строка модуль не удерживает», а не «значение не задано»: ключ с пустой составляющей считается выполненным (MATCH SIMPLE). Константа true сделала бы модуль неснимаемым навсегда — строка снятой роли не удаляется, на этом стоит обратимость (#1913).';

ALTER TABLE kaname.roles
  ADD CONSTRAINT roles_owner_module_live_fk
    FOREIGN KEY (owner_module, owner_module_live)
    REFERENCES kaname.catalog_module (module, live) MATCH SIMPLE
    ON DELETE NO ACTION ON UPDATE NO ACTION;

-- ── САМОПРОВЕРКА ИСХОДА И ПЕРЕПИСЬ ───────────────────────────────────────────
--
-- Утверждается ровно то, что эта миграция обещает: ключ существует и ПРОВЕРЕН,
-- живость ни одной строки не изменилась, и состояние «модуль снят при живой
-- роли» отсутствует. Перепись печатается ВСЕГДА — «ноль расхождений» обязано
-- быть отличимо от «ноль прочитанного», и она же называет цену переписывания
-- числом строк на ТОЙ базе, где миграция применяется.

-- +goose StatementBegin
DO $$
DECLARE
    before_all    int;
    before_live   int;
    before_owned  int;
    before_mods   int;
    after_all     int;
    after_live    int;
    after_owned   int;
    after_mods    int;
    key_present   int;
    key_valid     boolean;
    contradicted  int;
BEGIN
    SELECT roles_all, roles_live, roles_owned, modules_live
      INTO before_all, before_live, before_owned, before_mods
      FROM _roles_before;

    SELECT count(*) INTO key_present
      FROM pg_constraint
     WHERE conname = 'roles_owner_module_live_fk'
       AND conrelid = 'kaname.roles'::regclass;
    IF key_present <> 1 THEN
        RAISE EXCEPTION
            'ключ roles_owner_module_live_fk не заведён (найдено %): без него '
            'состояние «модуль снят, его роли живы и грантуют» остаётся '
            'представимым (kacho#2026)', key_present;
    END IF;

    SELECT convalidated INTO key_valid
      FROM pg_constraint
     WHERE conname = 'roles_owner_module_live_fk'
       AND conrelid = 'kaname.roles'::regclass;
    IF NOT key_valid THEN
        RAISE EXCEPTION
            'ключ roles_owner_module_live_fk не проверен: строки, лежавшие до '
            'него, под него не подпадают (kacho#2026)';
    END IF;

    -- Прежний ключ обязан ОСТАТЬСЯ: он утверждает «владелец известен платформе»
    -- БЕЗУСЛОВНО, тогда как ключ живости у снятой строки не проверяется вовсе.
    SELECT count(*) INTO key_present
      FROM pg_constraint
     WHERE conname = 'roles_owner_module_fk'
       AND conrelid = 'kaname.roles'::regclass;
    IF key_present <> 1 THEN
        RAISE EXCEPTION
            'прежний ключ roles_owner_module_fk снят (найдено %): ключ живости '
            'его НЕ замещает — у снятой строки он не проверяется вовсе '
            '(kacho#2026)', key_present;
    END IF;

    SELECT count(*) INTO after_all   FROM kaname.roles;
    SELECT count(*) INTO after_live  FROM kaname.roles WHERE live;
    SELECT count(*) INTO after_owned FROM kaname.roles WHERE owner_module IS NOT NULL;
    SELECT count(*) INTO after_mods  FROM kaname.catalog_module WHERE live;

    IF (after_all, after_live, after_owned, after_mods)
       IS DISTINCT FROM (before_all, before_live, before_owned, before_mods) THEN
        RAISE EXCEPTION
            'миграция изменила строки: было ролей %, живых %, с владельцем %, живых модулей %; '
            'стало %, %, %, % — ключ обязан менять ПРЕДСТАВИМОЕ, а не посеянное (kacho#2026)',
            before_all, before_live, before_owned, before_mods,
            after_all, after_live, after_owned, after_mods;
    END IF;

    -- Ключ только что провалидировал каждую строку, поэтому противоречие здесь
    -- невозможно. Проверка стоит не ради него, а ради того, чтобы перепись
    -- называла ОБЕ величины: «нарушений 0» при «прочитано 0» неотличимо от
    -- исправной работы.
    SELECT count(*) INTO contradicted
      FROM kaname.roles r
      JOIN kaname.catalog_module cm ON cm.module = r.owner_module
     WHERE r.live AND NOT cm.live;
    IF contradicted <> 0 THEN
        RAISE EXCEPTION
            'живых ролей у снятых модулей: % — ключ не удержал порядок (kacho#2026)',
            contradicted;
    END IF;

    RAISE NOTICE
        'ключ живости модуля-владельца: переписано строк roles %, из них живых %, '
        'с владельцем-модулем %; живых модулей %; живых ролей у снятых модулей %',
        after_all, after_live, after_owned, after_mods, contradicted;
END;
$$;
-- +goose StatementEnd

-- +goose Down
--
-- Откат снимает ПОРЯДОК, а не данные: ни одна строка не меняется. После него
-- состояние «модуль снят, его роли живы и грантуют» снова становится
-- представимым — и это надо знать тому, кто откат применяет.
ALTER TABLE kaname.roles
  DROP CONSTRAINT roles_owner_module_live_fk;

ALTER TABLE kaname.roles
  DROP COLUMN owner_module_live;
