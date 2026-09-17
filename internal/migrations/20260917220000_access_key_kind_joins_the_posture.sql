-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- access_key_kind_joins_the_posture — ЧЕТВЁРТЫЙ собственный вид учёта службы,
-- `iam.user.accessKey`: потолок числа ключей доступа у ОДНОГО человека (фаза
-- Ф7, задача PRO-Robotech/kacho#1273; приёмка
-- `docs/engineering/acceptance/access-keys-are-ours.md`, Р8, Ф7-37, Ф7-38;
-- §9 п. 7 — «вид заводится ДО первой строки, которая его считает»).
--
-- Санкция: одобренный сосед `credential-ceiling-per-principal.md` (Д1:
-- «потолок ставится на РЕСУРС, а не на значение его поля-дискриминатора») и
-- одобренный `retention-sweep-has-a-caller.md` («у каждой таблицы, чей рост
-- задаёт внешний, есть НАЗВАННЫЙ механизм ограничения»). Ключ — новый ресурс со
-- своей таблицей (Р1), значит и потолок у него свой; считать его в
-- `iam.user.credential` нельзя по тому же Д1 с другой стороны — подчинённый
-- ресурс `iam.credential` анкерен таблицами удостоверений, и таблица ключей в
-- их числе не стоит.
--
-- =============================================================================
-- ПОЧЕМУ ОТДЕЛЬНАЯ МИГРАЦИЯ, А НЕ СТРОКА В МИГРАЦИИ ТАБЛИЦЫ
-- =============================================================================
-- Множество видов закрыто ОГРАНИЧЕНИЕМ СХЕМЫ (`own_ceilings_kind_ck`): вид,
-- которого в нём нет, не попадает в проекцию посадки даже опечаткой, и ручка
-- посадки не имеет куда лечь. Триггер списания на таблице ключей ссылается на
-- вид — вид обязан существовать РАНЬШЕ таблицы. Обратный порядок дал бы
-- таблицу, растущую без механизма ограничения между двумя накатами.
--
-- Применённую миграцию не правят (ban #5): ограничение перевыражается здесь
-- снятием и заведением заново, с прежними тремя именами дословно.
--
-- ВЕЛИЧИНУ эта миграция НЕ объявляет: её объявляет посадка ручкой
-- `own-ceilings.access-keys-per-user`, и страж старта отказывает в пуске при
-- незаданной (Ф7-38). Ноль законен и означает «ключей не заводить». Порядок
-- «вид → перепись источника → величина → перенос» — §9 п. 7 приёмки: перенос
-- списывает те же слоты, и величина ниже наибольшего числа ключей у одного
-- человека роняет перенос предполётной переписью до первой строки (Ф7-43).

-- +goose Up

ALTER TABLE kaname.own_ceilings DROP CONSTRAINT own_ceilings_kind_ck;
ALTER TABLE kaname.own_ceilings ADD CONSTRAINT own_ceilings_kind_ck CHECK (kind = ANY (ARRAY[
    'iam.account'::text,
    'iam.user.credential'::text,
    'iam.serviceAccount.credential'::text,
    'iam.user.accessKey'::text]));

COMMENT ON TABLE kaname.own_ceilings IS 'projection of the deployment posture into the schema: the ceiling for each kind this service OWNS — accounts per identity, credentials per user, credentials per service account, access keys per user. Not an authority and not a smaller one — it has no contract, no scope arms, no seniority between them and no revision, and the only writer is the process start. It exists because the charge must happen in the same transaction as the resource row, and a trigger cannot read a process setting: the value has to lie next to the rows it bounds. Written by the composition root before any listener comes up; the startup guard refuses to boot while any of the four values is unstated or negative';

-- +goose Down

-- Откат снимает ВИД из закрытого множества и вместе с ним — его величину:
-- строка проекции с этим видом не прошла бы восстановленное ограничение.
-- Величину посадка проецирует заново на каждом старте, поэтому её снятие
-- ничего не уничтожает; таблица ключей и её триггер живут своей миграцией и
-- откатываются раньше этой (goose идёт в обратном порядке).
DELETE FROM kaname.own_ceilings WHERE kind = 'iam.user.accessKey';

ALTER TABLE kaname.own_ceilings DROP CONSTRAINT own_ceilings_kind_ck;
ALTER TABLE kaname.own_ceilings ADD CONSTRAINT own_ceilings_kind_ck CHECK (kind = ANY (ARRAY[
    'iam.account'::text,
    'iam.user.credential'::text,
    'iam.serviceAccount.credential'::text]));

COMMENT ON TABLE kaname.own_ceilings IS 'projection of the deployment posture into the schema: the ceiling for each kind this service OWNS. Not an authority and not a smaller one — it has no contract, no scope arms, no seniority between them and no revision, and the only writer is the process start. It exists because the charge must happen in the same transaction as the resource row, and a trigger cannot read a process setting: the value has to lie next to the rows it bounds. Written by the composition root before any listener comes up; the startup guard refuses to boot while any of the three values is unstated or negative';
