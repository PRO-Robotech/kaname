-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 0083_relation_fact — прямые факты отношения, не выводимые из выдачи.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧТО СЮДА ЛОЖИТСЯ И ЧТО НЕТ
--
-- Форма E отвечает на вопрос о доступе из ЧЕТЫРЁХ источников, и три из них у
-- iam уже есть своими таблицами:
--
--   выдача роли на область      → access_bindings + access_binding_subjects
--   выдача по меткам            → access_binding_selector
--   какие глаголы даёт роль     → role_rule_selectors
--   членство в группе           → group_members
--
-- Четвёртого не было: ПРЯМОЙ факт отношения, который не выводится ни из одной
-- выдачи. Это владение, поставленное в момент создания объекта, иерархический
-- указатель и подстановочный субъект — то, что сегодня живёт кортежами в чужом
-- хранилище и потому не может быть прочитано запросом к своей БД.
--
-- Сюда НЕ ложится то, что выводимо: дублировать выдачу фактом значило бы завести
-- второе место об одном предмете, которое разойдётся при первом же отзыве —
-- причём разойдётся молча, потому что оба места по отдельности непротиворечивы.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ СУБЪЕКТ ОДНОЙ КОЛОНКОЙ, А ОБЪЕКТ ДВУМЯ
--
-- Асимметрия намеренная и следует из того, КАК их спрашивают. Объект всегда
-- назван парой (тип, идентификатор) — так его называет вопрос, так он лежит в
-- зеркале и в рёбрах, и разбор строки на каждом соединении был бы лишней
-- работой на пути запроса.
--
-- Субъект спрашивается целиком: `"user:usr-1"`, `"group:grp-1#member"`,
-- `"user:*"`. Последние две формы — не пара «тип и идентификатор»: у одной есть
-- отношение-хвост, у другой вместо идентификатора подстановочный знак.
-- Разложить их на две колонки можно только выдумав правило разложения, которого
-- нет в самом имени.

-- +goose Up

CREATE TABLE kacho_iam.relation_fact (
  object_type    text NOT NULL,
  object_id      text NOT NULL,
  relation       text NOT NULL,
  subject        text NOT NULL,

  -- Версия состояния у источника — тот же смысл, что у зеркала и рёбер:
  -- устаревшая доставка не должна воскрешать снятый факт.
  source_version timestamptz NOT NULL DEFAULT '-infinity',
  created_at     timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT relation_fact_pkey
    PRIMARY KEY (object_type, object_id, relation, subject),

  CONSTRAINT relation_fact_object_type_nonempty CHECK (object_type <> ''),
  CONSTRAINT relation_fact_object_id_nonempty   CHECK (object_id   <> ''),
  CONSTRAINT relation_fact_relation_nonempty    CHECK (relation    <> ''),
  CONSTRAINT relation_fact_subject_nonempty     CHECK (subject     <> '')
);

-- Обратный вопрос: «какие объекты этот субъект держит по этому отношению».
-- Индекс по (subject, relation) — то, чем отвечают вопросы 5–6 поверхности
-- перечисления. Без него ответ на них — обход всей таблицы.
CREATE INDEX relation_fact_by_subject
  ON kacho_iam.relation_fact (subject, relation);

-- +goose Down

DROP TABLE IF EXISTS kacho_iam.relation_fact;
