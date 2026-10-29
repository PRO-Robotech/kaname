-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- module_admits_class_grants_only_on_containers — модуль решает публичность
-- своих объектов сам (стадия S7, задача PRO-Robotech/kaname#950).
--
-- Санкция: одобренная приёмка
-- `docs/engineering/acceptance/anonymous-and-authenticated-are-subject-classes.md`
-- (редакция 17, отпечаток d44a9bbbdfef42e5f33d0ded13754ff103a4ae33f7ad6d7695be3865b65f9ae7),
-- решение Р11 пп. 1 и 7: признак ключа оболочки манифеста
-- `classGrantsOnlyOnContainers` берётся из того же ЖИВОГО каталога, из которого
-- ворота SC-65 берут «тип объявлен», и действует с той же доставки манифеста.
--
-- ОДНА КОЛОНКА строки модуля каталога: `class_grants_only_on_containers` — модуль
-- объявил ключ. Это признак МОДУЛЯ, а не ресурса (Р11 п. 1), поэтому место ему —
-- `catalog_module`, рядом с редакцией. Пишет её применитель каталога
-- (`catalogWriter.UpsertModule`) из доставленного манифеста; читают ворота
-- выдачи системному классу (`system_class_gates.go`, SC-78, SC-81).
--
-- ОБРАТНОГО ЗАПОЛНЕНИЯ НЕТ и оно не нужно: ни один доставляемый сегодня манифест
-- ключа не несёт («Что НЕ входит» п. 8), и `false` у всех строк есть их точное
-- состояние. Действующих выдач колонка не трогает: их перепись — шаг выкатки
-- ключа («Что НЕ входит» п. 9).

-- +goose Up
ALTER TABLE kaname.catalog_module
    ADD COLUMN class_grants_only_on_containers boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN kaname.catalog_module.class_grants_only_on_containers IS 'Модуль объявил ключ оболочки манифеста classGrantsOnlyOnContainers: выдачу системному классу, достающую до его типов, он принимает только на объявленном контейнере публичного чтения (catalog_resource.public_read_to_children). Пишет применитель каталога из доставленного манифеста; читают ворота выдачи классу. kaname#950.';

-- +goose Down
ALTER TABLE kaname.catalog_module DROP COLUMN class_grants_only_on_containers;
