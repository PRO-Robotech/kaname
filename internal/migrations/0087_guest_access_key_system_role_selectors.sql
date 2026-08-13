-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- Расширение материализующих селекторов подстановочных системных ролей
-- (admin / edit / view / owner) новым видом `compute.guestAccessKey`.
--
-- ЗАЧЕМ. Ключ входа несёт свои метки и приезжает к владельцу прав тем же путём,
-- что машина, поэтому он вошёл в `domain.labelSelectableTypes`, а значит и в
-- `domain.AllMaterializableTypes()`. Если селектор подстановочной роли этого
-- вида НЕ называет, то свежесозданный ключ не сопоставляется с привязкой
-- редактора/владельца проекта, реконсайлер не материализует ни одного `v_*` —
-- и создатель получает отказ на СВОЁМ только что заведённом ключе. Объявить
-- тип в модели необходимо, но недостаточно: пока его не называет селектор
-- обнаружения привязок, право не материализуется ни для кого.
--
-- ПОЧЕМУ ИМЕННО ЭТИ ЧЕТЫРЕ СТРОКИ, А НЕ «ВСЕ, ГДЕ ЕСТЬ compute.instance».
-- Снятие вида (миграция 0074) законно проходило по всем селекторам, которые его
-- называли: сузить можно везде. Добавление несимметрично — расширив таким же
-- предикатом, мы дали бы права на ключи владельцу роли, которую арендатор
-- написал про машины. Правило `*.*` означает «всякий вид» по построению, и
-- только для него появление нового вида не расширяет замысла.
--
-- ФОРМА. Перечень здесь НЕ переписывается целиком: он уже лежит в строке, и
-- второе его изложение разошлось бы с первым на следующей же правке. Добавляем
-- элемент и пересортировываем, чтобы порядок остался тем же детерминированным,
-- какой производит проекция из Go.
--
-- Идемпотентно: условие `NOT (… = ANY(object_types))` делает повтор (и
-- самолечение при старте) пустой операцией. Аддитивно, применённые миграции не
-- правятся (ban #5). Следующая миграция: 0088.

UPDATE kacho_iam.role_rule_selectors
   SET object_types = (
         SELECT array_agg(t ORDER BY t)
           FROM unnest(object_types || ARRAY['compute.guestAccessKey']::text[]) AS t
       ),
       updated_at = now()
 WHERE NOT ('compute.guestAccessKey' = ANY(object_types))
   AND (
        (role_id = 'rol' || substr(md5('admin'), 1, 17) AND rule_fp = '3a9a54c3276716602674c9995c9321bea53a5ae693684842a389a80ecb1c80c4')
     OR (role_id = 'rol' || substr(md5('edit'),  1, 17) AND rule_fp = 'e4919459188e4b7b3786370b6c0899a79b4df159bd1988aef0b3ad23bb5aacfe')
     OR (role_id = 'rol' || substr(md5('view'),  1, 17) AND rule_fp = 'fe68d56d542e8b599256b1a7eee6e31eed6db358e7254af4b5e25c7195dcf68e')
     OR (role_id = 'rol' || substr(md5('owner'), 1, 17) AND rule_fp = '3a9a54c3276716602674c9995c9321bea53a5ae693684842a389a80ecb1c80c4')
   );

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Обратный путь снимает вид из тех же четырёх строк. Он безопасен ровно в ту
-- сторону, в какую несимметрично добавление: сузить можно всегда.
UPDATE kacho_iam.role_rule_selectors
   SET object_types = array_remove(object_types, 'compute.guestAccessKey'),
       updated_at   = now()
 WHERE 'compute.guestAccessKey' = ANY(object_types);

-- +goose StatementEnd
