-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- access_binding_target_form_is_validated — проверка лежащих строк выдач
-- ограничением формы цели (задача PRO-Robotech/kaname#863, находка ревью
-- DB-863-2).
--
-- Ограничение `access_bindings_target_form_ck` заведено предыдущей миграцией
-- (`20261018090644_access_binding_target_form_is_held_by_the_base.sql`)
-- `NOT VALID`: новые и обновлённые строки оно судит с того момента, лежащие —
-- нет. Здесь оно проверяется: `VALIDATE CONSTRAINT` читает таблицу целиком и
-- помечает ограничение проверенным. Строка вне формы останавливает накат с
-- SQLSTATE 23514 и именем ограничения — молча она не остаётся. Перепись
-- нарушителей на версии до заведения — ноль (проба
-- `access_binding_target_form_integration_test.go` печатает её числом).
--
-- ЗАМОК. goose ведёт эту миграцию своей транзакцией, отдельно от заведения.
-- `VALIDATE CONSTRAINT` берёт на таблицу `SHARE UPDATE EXCLUSIVE`: чтение и
-- запись выдач при проходе идут, решение о доступе в очередь не встаёт
-- (проба читает режим из `pg_locks` транзакции наката). Замер ревью DB-863-2:
-- 6,1 с на 1 000 000 выдач, postgres:16. Этот замок конфликтует не с
-- чтением и записью строк, а с изменением схемы таблицы, построением индекса,
-- очисткой и анализом; `lock_timeout` ограничивает ожидание такого соседа.
--
-- ОТКАТ возвращает ровно состояние предыдущей версии — ограничение на месте,
-- но не проверено: снятие и повторное заведение `NOT VALID` таблицу не
-- читают. Снимает ограничение откат предыдущей миграции.

-- +goose Up
SET LOCAL lock_timeout = '5s';

ALTER TABLE kaname.access_bindings VALIDATE CONSTRAINT access_bindings_target_form_ck;

-- +goose Down
SET LOCAL lock_timeout = '5s';

ALTER TABLE kaname.access_bindings DROP CONSTRAINT access_bindings_target_form_ck;

ALTER TABLE kaname.access_bindings
    ADD CONSTRAINT access_bindings_target_form_ck CHECK (kaname.access_target_form_valid(target)) NOT VALID;
