-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- Расширение материализующих селекторов подстановочных системных ролей
-- (admin / edit / view / owner) новым видом `compute.placementGroup`.
--
-- Обоснование то же, что у миграции 0087, и оно не риторическое: пока селектор
-- обнаружения привязок вида не называет, реконсайлер не материализует ни одного
-- `v_*`, и создатель получает отказ на СВОЕЙ только что заведённой группе.
-- Объявить тип в модели необходимо, но недостаточно.
--
-- Правятся ровно четыре строки правила `*.*`: добавление НЕСИММЕТРИЧНО снятию.
-- Расширив предикатом «все селекторы, где есть compute.instance», мы дали бы
-- права на группы владельцу роли, которую арендатор написал про машины.
--
-- Перечень не переписывается целиком: он уже лежит в строке, и второе его
-- изложение разошлось бы с первым на следующей правке.
--
-- Идемпотентно; аддитивно; применённые миграции не правятся. Следующая: 0089.

UPDATE kacho_iam.role_rule_selectors
   SET object_types = (
         SELECT array_agg(t ORDER BY t)
           FROM unnest(object_types || ARRAY['compute.placementGroup']::text[]) AS t
       ),
       updated_at = now()
 WHERE NOT ('compute.placementGroup' = ANY(object_types))
   AND (
        (role_id = 'rol' || substr(md5('admin'), 1, 17) AND rule_fp = '3a9a54c3276716602674c9995c9321bea53a5ae693684842a389a80ecb1c80c4')
     OR (role_id = 'rol' || substr(md5('edit'),  1, 17) AND rule_fp = 'e4919459188e4b7b3786370b6c0899a79b4df159bd1988aef0b3ad23bb5aacfe')
     OR (role_id = 'rol' || substr(md5('view'),  1, 17) AND rule_fp = 'fe68d56d542e8b599256b1a7eee6e31eed6db358e7254af4b5e25c7195dcf68e')
     OR (role_id = 'rol' || substr(md5('owner'), 1, 17) AND rule_fp = '3a9a54c3276716602674c9995c9321bea53a5ae693684842a389a80ecb1c80c4')
   );

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

UPDATE kacho_iam.role_rule_selectors
   SET object_types = array_remove(object_types, 'compute.placementGroup'),
       updated_at   = now()
 WHERE 'compute.placementGroup' = ANY(object_types);

-- +goose StatementEnd
