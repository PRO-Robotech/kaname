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
--      (глаголы правила зависят от каталога и от развёртки подстановок), поэтому:
--   3. `kaname.role_selector_verbs_pending` — очередь ролей, чьи строки несут
--      набор, выведенный здесь. Пересчёт на старте службы
--      (`seed.ReseedSystemRoleVerbs`) пишет точный набор по отпечатку правила и
--      снимает роль из очереди; правка роли (`ReplaceRuleSelectors`) снимает её
--      тем же оператором транзакции. Пустая очередь — пересчитывать нечего, и
--      чтение её на старте не трогает ни одной строки.
--
-- ПОЧЕМУ КАРТА НА СЕЛЕКТОРЕ, А НЕ ПРАВИЛО В КЛЮЧЕ `role_verb`. Ключ с правилом
-- дал бы решению о доступе по строке проекции на КАЖДОЕ правило, накрывшее
-- объект, сверх строки селектора: на оси «правил роли, накрывших объект» сетки
-- прочности это вдвое больше прочитанного. Карта читается из уже прочитанной
-- строки селектора — обращений не прибавляет, а проекция роли остаётся первым
-- отсевом вопроса о глаголе, которого роль не даёт вовсе.

-- +goose Up
ALTER TABLE kaname.role_rule_selectors
    ADD COLUMN verbs_by_type jsonb;

UPDATE kaname.role_rule_selectors s
   SET verbs_by_type = coalesce((
         SELECT jsonb_object_agg(t.dotted, v.verbs)
           FROM (SELECT DISTINCT u.dotted FROM unnest(s.object_types) AS u(dotted)) t
           CROSS JOIN LATERAL (
                  SELECT jsonb_agg(rv.verb ORDER BY rv.verb) AS verbs
                    FROM kaname.role_verb rv
                   WHERE rv.role_id = s.role_id AND rv.object_type = t.dotted) v
          WHERE v.verbs IS NOT NULL), '{}'::jsonb);

ALTER TABLE kaname.role_rule_selectors
    ALTER COLUMN verbs_by_type SET NOT NULL,
    ADD CONSTRAINT role_rule_selectors_verbs_obj CHECK (jsonb_typeof(verbs_by_type) = 'object');

COMMENT ON COLUMN kaname.role_rule_selectors.verbs_by_type IS 'Глаголы, которые ЭТО правило даёт на каждом своём типе: ключ — точечный тип из object_types, значение — массив глаголов. Решение о доступе даёт глагол на объекте только тем правилом, чей селектор объект выбрал (kaname#878). Вычисляет код по живому каталогу тем же предикатом, что проекцию роли role_verb (она — объединение этих карт); пустая карта — правило не даёт ничего. Строки, заполненные миграцией 20261018030000, несут объединение по роли до пересчёта (очередь role_selector_verbs_pending).';

COMMENT ON TABLE kaname.role_verb IS 'Проекция «роль → тип объекта × глагол» — объединение глаголов всех правил роли. Цепь вердикта читает её ПЕРВЫМ отсевом: глагол, которого роль не даёт вовсе, отвергается до чтения селекторов; глагол на объекте даёт только правило, чей селектор объект выбрал (role_rule_selectors.verbs_by_type, kaname#878). АВТОР один — role_repo.ReplaceRoleVerbs: форму строки объявляет только тот, кто её вносит. Снимать вправе и не-автор (применитель каталога, когда снят ресурс, на который ссылается role_verb_type_fk), но снятое он обязан ПЕРЕСЕЛИТЬ в role_grant_orphan тем же оператором.';

CREATE TABLE kaname.role_selector_verbs_pending (
    role_id     text PRIMARY KEY REFERENCES kaname.roles (id) ON DELETE CASCADE,
    enqueued_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE kaname.role_selector_verbs_pending IS 'Роли, чьи строки селекторов несут глаголы, выведенные миграцией 20261018030000 объединением по роли, а не вычисленные по правилу (kaname#878). Снимает роль пересчёт на старте службы (seed.ReseedSystemRoleVerbs → RegrainSelectorVerbs) либо правка роли (ReplaceRuleSelectors) — тем же оператором транзакции, что пишет точный набор. Новых строк не получает: роль, заведённая после миграции, пишет точный набор сразу.';

INSERT INTO kaname.role_selector_verbs_pending (role_id)
SELECT DISTINCT s.role_id FROM kaname.role_rule_selectors s;

-- +goose Down
DROP TABLE kaname.role_selector_verbs_pending;

COMMENT ON TABLE kaname.role_verb IS 'Проекция «роль → тип объекта × глагол» — то, из чего цепь вердикта собирает ответ «разрешено ли действие». АВТОР один — role_repo.ReplaceRoleVerbs: форму строки объявляет только тот, кто её вносит. Снимать вправе и не-автор (применитель каталога, когда снят ресурс, на который ссылается role_verb_type_fk), но снятое он обязан ПЕРЕСЕЛИТЬ в role_grant_orphan тем же оператором.';

ALTER TABLE kaname.role_rule_selectors
    DROP CONSTRAINT role_rule_selectors_verbs_obj,
    DROP COLUMN verbs_by_type;
