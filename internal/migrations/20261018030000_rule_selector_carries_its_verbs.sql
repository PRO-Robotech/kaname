-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- rule_selector_carries_its_verbs — строка селектора правила роли несёт глаголы
-- ЭТОГО правила (задача PRO-Robotech/kaname#878).
--
-- ПРЕДМЕТ. Решение о доступе соединяло проекцию «роль → тип × глагол»
-- (`role_verb`, объединение глаголов ВСЕХ правил роли) с селектором правила
-- только по роли и типу. Глагол одного правила сочетался с охватом другого:
-- у роли из правил «чтение всех реестров» и «удаление реестра X» удаление
-- выходило на все реестры. Материализатор считает глаголы по правилу; теперь и
-- решение о доступе читает глаголы с самой строки селектора.
--
-- ЧТО МЕНЯЕТСЯ:
--
--   1. `kaname.role_rule_selectors.verbs_by_type` — карта «точечный тип →
--      глаголы, которые ЭТО правило даёт на типе». Вычисляет её код по живому
--      каталогу (`catalog.Facts.GrantSelectors`) тем же предикатом, что
--      проекцию роли: проекция роли есть объединение этих карт. Ключи —
--      подмножество `object_types`.
--   2. Заполнение существующих строк — ОБЪЕДИНЕНИЕМ по роли: каждой строке
--      достаются все глаголы проекции роли на её типах. Это ровно то, что
--      решение о доступе давало до этой миграции, — доступа миграция не
--      отнимает и не добавляет. Точный набор по правилу вычисляет только код
--      (глаголы правила зависят от каталога и от развёртки подстановок), и роль
--      встаёт в очередь пересчёта (п. 5).
--   3. Страж живости типов селектора будится записью тех колонок, которые он
--      судит и выводит (`object_types`, `container_type`,
--      `container_object_type`), а не любой записью строки: запись карты
--      глаголов ссылок на каталог не меняет.
--   4. Инвариант карты держит СХЕМА: проверка `role_rule_selectors_verbs_valid`
--      (функция `role_selector_verbs_valid`, IMMUTABLE) — ключи подмножество
--      `object_types`, значения непустые массивы строк.
--   5. «Не вычислено» — отдельное состояние: роль в очереди
--      `kaname.role_selector_verbs_pending`. Её строки несут ВЕРХНЮЮ ГРАНИЦУ:
--      заполненные здесь — объединение по роли, вставленные без карты —
--      живые глаголы типа (`role_selector_verbs_upper_bound`). Решение о
--      доступе пересекает карту с проекцией роли, поэтому верхняя граница даёт
--      ровно прежнее поведение, а не шире. Пустой карты в значении «не
--      вычислено» нет: пустая карта — «правило не даёт ничего».
--   6. ПЕРЕХОДНЫЙ страж `role_rule_selectors_verbs_uncomputed`: вставка без
--      карты (писатель прежней версии службы во время перекатки) получает
--      верхнюю границу и ставит роль в очередь, а не отказ 23502, который
--      дошёл бы до арендатора ложным «неверный аргумент».
--
-- ОЧЕРЕДЬ ПУСТЕЕТ пересчётом службы (`seed.DrainSelectorVerbsQueue`): проход
-- по ролям очереди, каждая — своей транзакцией, повтор до пустой очереди,
-- перепись каждого прохода с длиной очереди. Правка роли снимает её тем же
-- оператором транзакции, что пишет точные карты.
--
-- ПРЕДИКАТ СНЯТИЯ переходного механизма (страж 6, функция верхней границы для
-- него, цикл пересчёта очереди): очередь пуста на всех установках и
-- писателей прежней версии не осталось —
--   SELECT count(*) FROM kaname.role_selector_verbs_pending  →  0
-- на каждой установке после выкатки этой версии. Досев селекторов системной
-- роли очередью пользуется и после (новая строка ложится «не вычисленной»),
-- поэтому таблица очереди переходным механизмом не является.
--
-- ПОЧЕМУ КАРТА НА СЕЛЕКТОРЕ, А НЕ ПРАВИЛО В КЛЮЧЕ `role_verb`. Ключ с правилом
-- дал бы решению о доступе по строке проекции на КАЖДОЕ правило, накрывшее
-- объект, сверх строки селектора: на оси «правил роли, накрывших объект» сетки
-- прочности это вдвое больше прочитанного. Карта читается из уже прочитанной
-- строки селектора — обращений не прибавляет, а проекция роли остаётся первым
-- отсевом вопроса о глаголе, которого роль не даёт вовсе.

-- +goose Up
SET LOCAL lock_timeout = '10s';

CREATE TABLE kaname.role_selector_verbs_pending (
    role_id     text PRIMARY KEY REFERENCES kaname.roles (id) ON DELETE CASCADE,
    enqueued_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE kaname.role_selector_verbs_pending IS 'Роли, у которых карта глаголов правил (role_rule_selectors.verbs_by_type) НЕ ВЫЧИСЛЕНА: строки несут верхнюю границу — объединение по роли (миграция 20261018030000) либо живые глаголы типа (досев системной роли, переходный страж role_rule_selectors_verbs_uncomputed). Снимает роль пересчёт службы (seed.DrainSelectorVerbsQueue, seed.ReseedSystemRoleVerbs → RegrainSelectorVerbs) либо правка роли (ReplaceRuleSelectors) — тем же оператором транзакции, что пишет точные карты. kaname#878.';

ALTER TABLE kaname.role_rule_selectors
    ADD COLUMN verbs_by_type jsonb;

-- Страж живости типов судит и выводит ССЫЛКИ строки на каталог — элементы
-- `object_types`, тип контейнера и его модельное имя. Запись одной карты
-- глаголов ссылок не меняет; будить на ней стража значило бы отвергать
-- пересчёт у строки, чей тип снят каталогом позже её записи (у системной роли
-- применитель селекторы не укорачивает), и заполнение ниже упало бы на них.
DROP TRIGGER role_rule_selectors_types_live ON kaname.role_rule_selectors;
CREATE TRIGGER role_rule_selectors_types_live
    BEFORE INSERT OR UPDATE OF object_types, container_type, container_object_type
    ON kaname.role_rule_selectors
    FOR EACH ROW EXECUTE FUNCTION kaname.role_rule_selector_types_live();

-- +goose StatementBegin
CREATE FUNCTION kaname.role_selector_verbs_valid(p_verbs jsonb, p_types text[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    AS $$
    SELECT jsonb_typeof(p_verbs) = 'object'
       AND NOT EXISTS (
             SELECT 1
               FROM jsonb_each(p_verbs) AS e(k, v)
              WHERE NOT (e.k = ANY (p_types))
                 OR jsonb_typeof(e.v) <> 'array'
                 OR jsonb_array_length(e.v) = 0
                 OR EXISTS (SELECT 1 FROM jsonb_array_elements(e.v) AS x(item)
                             WHERE jsonb_typeof(x.item) <> 'string'))
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.role_selector_verbs_valid(jsonb, text[]) IS 'Форма карты глаголов правила: объект, ключи — подмножество типов строки селектора, значения — непустые массивы строк. kaname#878.';

-- +goose StatementBegin
CREATE FUNCTION kaname.role_selector_verbs_upper_bound(p_types text[]) RETURNS jsonb
    LANGUAGE sql STABLE
    AS $$
    SELECT coalesce(jsonb_object_agg(t.dotted, v.verbs), '{}'::jsonb)
      FROM (SELECT DISTINCT u.dotted FROM unnest(p_types) AS u(dotted)) t
      CROSS JOIN LATERAL (
             SELECT jsonb_agg(DISTINCT lower(btrim(cv.verb))) AS verbs
               FROM kaname.catalog_resource cr
               JOIN kaname.catalog_verb cv ON cv.module = cr.module AND cv.resource = cr.resource
              WHERE cr.dotted = t.dotted AND cr.live AND cv.live) v
     WHERE v.verbs IS NOT NULL
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.role_selector_verbs_upper_bound(text[]) IS 'Верхняя граница карты глаголов правила, пока точная не вычислена: живые глаголы каждого живого типа. Решение о доступе пересекает карту с проекцией роли, поэтому граница даёт поведение «по роли», а не шире. Читают досев селекторов системной роли и переходный страж role_rule_selectors_verbs_uncomputed. kaname#878.';

UPDATE kaname.role_rule_selectors s
   SET verbs_by_type = coalesce((
         SELECT jsonb_object_agg(t.dotted, v.verbs)
           FROM (SELECT DISTINCT u.dotted FROM unnest(s.object_types) AS u(dotted)) t
           CROSS JOIN LATERAL (
                  SELECT jsonb_agg(rv.verb ORDER BY rv.verb) AS verbs
                    FROM kaname.role_verb rv
                   WHERE rv.role_id = s.role_id AND rv.object_type = t.dotted) v
          WHERE v.verbs IS NOT NULL), '{}'::jsonb);

INSERT INTO kaname.role_selector_verbs_pending (role_id)
SELECT DISTINCT s.role_id FROM kaname.role_rule_selectors s;

ALTER TABLE kaname.role_rule_selectors
    ALTER COLUMN verbs_by_type SET NOT NULL,
    ADD CONSTRAINT role_rule_selectors_verbs_valid
        CHECK (kaname.role_selector_verbs_valid(verbs_by_type, object_types));

COMMENT ON COLUMN kaname.role_rule_selectors.verbs_by_type IS 'Глаголы, которые ЭТО правило даёт на каждом своём типе: ключ — точечный тип из object_types, значение — непустой массив глаголов (проверка role_rule_selectors_verbs_valid). Решение о доступе даёт глагол на объекте только тем правилом, чей селектор объект выбрал (kaname#878). Вычисляет код по живому каталогу тем же предикатом, что проекцию роли role_verb (она — объединение этих карт); пустая карта — правило не даёт ничего. Пока роль в очереди role_selector_verbs_pending, карта — верхняя граница, а не точный набор.';

-- +goose StatementBegin
CREATE FUNCTION kaname.role_rule_selectors_verbs_uncomputed() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.verbs_by_type := kaname.role_selector_verbs_upper_bound(NEW.object_types);
    INSERT INTO kaname.role_selector_verbs_pending (role_id) VALUES (NEW.role_id)
        ON CONFLICT (role_id) DO NOTHING;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER role_rule_selectors_verbs_uncomputed
    BEFORE INSERT ON kaname.role_rule_selectors
    FOR EACH ROW WHEN (NEW.verbs_by_type IS NULL)
    EXECUTE FUNCTION kaname.role_rule_selectors_verbs_uncomputed();

COMMENT ON FUNCTION kaname.role_rule_selectors_verbs_uncomputed() IS 'ПЕРЕХОДНЫЙ страж перекатки (kaname#878): строка селектора, вставленная писателем прежней версии службы без карты глаголов, получает верхнюю границу и ставит роль в очередь пересчёта — вместо отказа 23502, который дошёл бы до арендатора ложным «неверный аргумент». Предикат снятия: очередь role_selector_verbs_pending пуста на всех установках после выкатки версии с этой миграцией.';

COMMENT ON TABLE kaname.role_verb IS 'Проекция «роль → тип объекта × глагол» — объединение глаголов всех правил роли. Цепь вердикта читает её ПЕРВЫМ отсевом: глагол, которого роль не даёт вовсе, отвергается до чтения селекторов; глагол на объекте даёт только правило, чей селектор объект выбрал (role_rule_selectors.verbs_by_type, kaname#878). АВТОР один — role_repo.ReplaceRoleVerbs: форму строки объявляет только тот, кто её вносит. Снимать вправе и не-автор (применитель каталога, когда снят ресурс, на который ссылается role_verb_type_fk), но снятое он обязан ПЕРЕСЕЛИТЬ в role_grant_orphan тем же оператором.';

-- +goose Down
SET LOCAL lock_timeout = '10s';

DROP TRIGGER role_rule_selectors_verbs_uncomputed ON kaname.role_rule_selectors;
DROP FUNCTION kaname.role_rule_selectors_verbs_uncomputed();

DROP TABLE kaname.role_selector_verbs_pending;

DROP TRIGGER role_rule_selectors_types_live ON kaname.role_rule_selectors;
CREATE TRIGGER role_rule_selectors_types_live
    BEFORE INSERT OR UPDATE ON kaname.role_rule_selectors
    FOR EACH ROW EXECUTE FUNCTION kaname.role_rule_selector_types_live();

COMMENT ON TABLE kaname.role_verb IS 'Проекция «роль → тип объекта × глагол» — то, из чего цепь вердикта собирает ответ «разрешено ли действие». АВТОР один — role_repo.ReplaceRoleVerbs: форму строки объявляет только тот, кто её вносит. Снимать вправе и не-автор (применитель каталога, когда снят ресурс, на который ссылается role_verb_type_fk), но снятое он обязан ПЕРЕСЕЛИТЬ в role_grant_orphan тем же оператором.';

ALTER TABLE kaname.role_rule_selectors
    DROP CONSTRAINT role_rule_selectors_verbs_valid,
    DROP COLUMN verbs_by_type;

DROP FUNCTION kaname.role_selector_verbs_upper_bound(text[]);
DROP FUNCTION kaname.role_selector_verbs_valid(jsonb, text[]);
