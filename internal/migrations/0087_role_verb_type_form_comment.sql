-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- Комментарий колонки приведён к тому, что кладёт писатель.
--
-- Миграция проекции глаголов объявляла, что в `object_type` лежит тип в форме
-- модели прав. Писатель кладёт ТОЧЕЧНУЮ форму — ту же, какой названы типы в
-- селекторах правил роли. Читатель, поверивший комментарию, соединял колонку с
-- вопросом о доступе, который приходит формой модели, и соединение не совпадало
-- НИКОГДА: исход выглядел как «права нет», а не как ошибка.
--
-- Прежняя миграция НЕ правится (применённую не редактируем): расхождение
-- снимается новой, и это единственный способ, при котором развёрнутая база и
-- дерево остаются согласны.

-- +goose Up
COMMENT ON COLUMN kacho_iam.role_verb.object_type IS
  'Тип объекта в ТОЧЕЧНОЙ форме (iam.account, vpc.network) — той же, какой названы типы в role_rule_selectors.object_types. НЕ форма модели прав (vpc_network): вопрос о доступе приходит ею, и перевод делается на входе читателя.';

COMMENT ON COLUMN kacho_iam.role_rule_selectors.object_types IS
  'Типы объектов в ТОЧЕЧНОЙ форме. Один словарь с role_verb.object_type: соединение по разным написаниям не совпадает никогда и молча.';

-- +goose Down
COMMENT ON COLUMN kacho_iam.role_verb.object_type IS NULL;
COMMENT ON COLUMN kacho_iam.role_rule_selectors.object_types IS NULL;
