-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- access_binding_target_form_is_held_by_the_base — форму цели привязки
-- (`access_bindings.target`) держит база, а не писатель (задача
-- PRO-Robotech/kaname#863, находка ревью kaname#862 по линии #857).
--
-- Санкция: задача #863 (P2, корректность). Публичный контракт не меняется:
-- через API записывается ровно та же пара форм, что и прежде
-- (`{"allInScope":true}` и `{"resources":[…]}`); ограничение отвергает лишь то,
-- чего писатель не пишет.
--
-- ПРИЗНАК. До этой миграции колонку судило одно ограничение —
-- `access_bindings_target_resources_card_ck`, число элементов перечня, — и всё,
-- что перечнем не было, оно пропускало. На таких формах два читателя цели
-- расходились: ветвь выдач решения о доступе давала отказ, материализатор
-- читал `{"resources": null}` как всю область, а `resources` строкой либо
-- объектом ломал загрузку выдачи. Отказ и «вся область» на одной строке — это
-- лишний доступ по одной стороне и его отсутствие по другой.
--
-- ЧТО ВВОДИТСЯ — функция формы и ограничение на ней; данных не трогает ни одна
-- строка:
--
--   1. `kaname.access_target_form_valid(jsonb)` — форма цели целиком: корень —
--      объект; `allInScope`, если есть, — логическое значение; `resources`, если
--      есть, — перечень, каждый элемент которого — объект со строковыми `type`
--      и `id`. Элементы судятся здесь же, потому что на них читатели расходились
--      тем же образом: элемент без строкового `id` материализатор не загружал,
--      а решение о доступе молча пропускало. Функция неизменяемая — её тело
--      читает только аргумент, поэтому она годна для ограничения.
--   2. `access_bindings_target_form_ck` — ограничение на функции, заводится
--      `NOT VALID`: новые и обновлённые строки оно судит с момента заведения,
--      а лежащие строки проверяет следующая миграция
--      (`20261018104759_access_binding_target_form_is_validated.sql`). SQLSTATE
--      нарушения — 23514. Форму цели сериализует служба
--      (`relverdict.EncodeTarget`), вызывающий шлёт поля контракта, а не JSON
--      колонки, — поэтому перепись полос проверок (`check_value_lanes.go`)
--      относит ограничение к полосе дефекта службы: отказ отвечает
--      фиксированным INTERNAL с записью в журнал, а не текстом вызывающему.
--
-- ЛЯЖЕТ ЛИ НА ЖИВЫЕ СТРОКИ. Писатели колонки в дереве
-- (`git grep -n 'INSERT INTO \(kaname\.\)\?access_bindings'` вне проб) пишут
-- законную форму: `marshalTarget` — `{"allInScope":true}` либо перечень пар
-- строк; посев базовой схемы и посевы двух миграций — `{"allInScope": true}`;
-- посев модульных выдач и обратное заполнение владельцев — значение колонки по
-- умолчанию, тот же `{"allInScope": true}`. Перепись нарушителей на версии до
-- этой миграции — ноль (проба `access_binding_target_form_integration_test.go`
-- печатает её числом), поэтому обратное заполнение не нужно. Строка вне формы
-- всё равно останавливает накат — его следующей миграцией, проверкой лежащих
-- строк, а не остаётся лежать молча: это и есть то свойство, ради которого
-- миграции заведены.
--
-- ЗАМОК. `ALTER TABLE … ADD CONSTRAINT … NOT VALID` берёт на таблицу
-- исключительный замок, но таблицу не читает: заведение — изменение каталога,
-- и замок держится до фиксации этой транзакции, которая больше ничего не
-- делает (замер ревью DB-863-2: 0,4 мс на 1 000 000 выдач, postgres:16).
-- Проход по таблице — в следующей миграции, своей транзакцией goose, под
-- `SHARE UPDATE EXCLUSIVE`: чтение и запись выдач при нём идут. Заведённое
-- ПРОВЕРЕННЫМ одним файлом держало бы исключительный замок весь проход — по
-- замеру того же ревью 6,0 с на 1 000 000 выдач, и всё это время каждое
-- решение о доступе стояло бы в очереди за ним.
--
-- `lock_timeout` ограничивает только ОЖИДАНИЕ замка: если таблицу держит
-- долгая транзакция, накат отказывает через 5 с, вместо того чтобы встать в
-- очередь и выстроить за собой все следующие запросы к выдачам. Очередь,
-- возникающую, пока замок УДЕРЖИВАЕТСЯ, он не ограничивает — её ограничивает
-- то, что замок держится лишь на время изменения каталога.

-- +goose Up
SET LOCAL lock_timeout = '5s';

-- +goose StatementBegin
CREATE FUNCTION kaname.access_target_form_valid(t jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $$
  SELECT jsonb_typeof(t) = 'object'
     AND (NOT t ? 'allInScope' OR jsonb_typeof(t -> 'allInScope') = 'boolean')
     AND (NOT t ? 'resources'
          OR (jsonb_typeof(t -> 'resources') = 'array'
              AND NOT EXISTS (
                  SELECT 1
                    FROM jsonb_array_elements(t -> 'resources') AS e(v)
                   WHERE jsonb_typeof(e.v) <> 'object'
                      OR jsonb_typeof(e.v -> 'type') IS DISTINCT FROM 'string'
                      OR jsonb_typeof(e.v -> 'id') IS DISTINCT FROM 'string')))
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.access_target_form_valid(jsonb) IS
    'Форма цели привязки: корень-объект; allInScope — логическое; resources — перечень объектов со строковыми type и id (kaname#863).';

ALTER TABLE kaname.access_bindings
    ADD CONSTRAINT access_bindings_target_form_ck CHECK (kaname.access_target_form_valid(target)) NOT VALID;

-- +goose Down
SET LOCAL lock_timeout = '5s';

ALTER TABLE kaname.access_bindings DROP CONSTRAINT IF EXISTS access_bindings_target_form_ck;

DROP FUNCTION IF EXISTS kaname.access_target_form_valid(jsonb);
