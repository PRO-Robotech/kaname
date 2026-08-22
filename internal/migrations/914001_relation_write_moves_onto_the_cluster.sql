-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 914001_relation_write_moves_onto_the_cluster — право модуля писать кортежи
-- переезжает с якоря ВНЕ ИЕРАРХИИ на КЛАСТЕРНОЕ отношение и становится обычной
-- системной выдачей.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ (#914, решение 1)
--
-- #893/#895 перевели встроенный доступ платформы на поверхность выдач для якорей
-- иерархии `cluster → account → project`. Право модуля писать кортежи туда не
-- попало: оно висело на служебном синглтоне — объекте, у которого нет ни яруса,
-- ни владельца. Следствия наблюдаемы и все три названы числом переписью
-- `TestIntegration_R893_NoEffectiveAccessOutsideTheGrantSurface`: перечисление
-- выдач о таком основании молчит, отзыв работает над выдачей, а её нет, и
-- «ничего не выдано» неотличимо от «выдано в обход».
--
-- Решение записано в
-- `services/iam/docs/engineering/architecture/grant-surface-boundaries.md`:
-- словарь якорей выдачи за пределы трёх ярусов НЕ растёт. У кластера все три
-- ответа уже есть — владелец (администратор облака), отзыв его же поверхностью,
-- определённая вложенность, — а модуль пишет кортежи для ВСЕХ арендаторов сразу,
-- то есть его право и есть право уровня кластера by construction.
--
-- ЦЕНА НАЗВАНА. Право становится шире ОБЪЯВЛЕННОГО: кластерное отношение видно
-- на кластере, а не на синглтоне. Фактического доступа это не расширяет — модуль
-- и прежде писал кортежи по всему кластеру, — но объявление становится честным,
-- а отзыв перестаёт требовать знания о синглтоне.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ГРУППА, А НЕ ПЕРЕЧИСЛЕНИЕ УЧЁТОК
--
-- Получателей пятеро, и состав меняется с каждым новым доменом, который начнёт
-- регистрировать свои ресурсы (два последних — реестр и хранилище — пришли
-- отдельными миграциями уже после первой). Право, чей состав получателей
-- меняется, выдаётся ГРУППЕ (`data-integrity.md` B18): снять одного из группы —
-- одна строка членства, снять одного из перечисления — снятие кортежей по всем
-- объектам. Прецедент того же вида в этом же дереве — группа читателей пределов
-- (миграции 0093/0096).
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ СОСТАВ ЧИТАЕТСЯ ИЗ ФАКТА, А НЕ ВЫПИСЫВАЕТСЯ
--
-- Учётки, у которых это право есть, завели ТРИ разные миграции (0009 · 0044 ·
-- 0057), и следующая придёт с очередным доменом. Выписанный здесь список
-- разошёлся бы с деревом молча — и разошёлся бы ровно в ту сторону, где модуль
-- остался бы без права и перестал писать владение для своих арендаторов.
-- Поэтому состав берётся из действующего основания доступа: переносится ровно
-- то, что действует, ни больше ни меньше.

-- +goose Up
-- +goose StatementBegin

-- ── 1. Группа пишущих кортежи (в системном аккаунте, что и модульные учётки) ──
INSERT INTO kacho_iam.groups (id, account_id, name, description)
VALUES (
  'grp' || substr(md5('module.relation_writers'), 1, 17),
  'acc' || substr(md5('kacho-system'), 1, 17),
  'module-relation-writers',
  'Module service accounts allowed to write relation tuples through iam (issue #914)'
)
ON CONFLICT (id) DO NOTHING;

-- +goose StatementEnd
-- +goose StatementBegin

-- ── 2. Состав — из действующего основания доступа на снимаемом якоре ─────────
INSERT INTO kacho_iam.group_members (group_id, member_type, member_id)
SELECT 'grp' || substr(md5('module.relation_writers'), 1, 17),
       'service_account',
       split_part(f.subject, ':', 2)
  FROM kacho_iam.relation_fact f
 WHERE f.object_type = 'iam_fgaproxy'
   AND f.relation    = 'fga_writer'
   AND split_part(f.subject, ':', 1) = 'service_account'
   AND split_part(f.subject, ':', 2) <> ''
ON CONFLICT DO NOTHING;

-- +goose StatementEnd
-- +goose StatementBegin

-- ── 3. Кортежи членства ─────────────────────────────────────────────────────
--
-- Членство не выводится из строки `group_members` само — оно материализуется
-- кортежем (прецедент посева — миграция 0029). Идёт через журнал намерений, из
-- которого проекция кладёт прямой факт в этом же коммите.
INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
SELECT 'fga.tuple.write',
       jsonb_build_object(
         'user',     'service_account:' || gm.member_id,
         'relation', 'member',
         'object',   'group:' || gm.group_id),
       now()
  FROM kacho_iam.group_members gm
 WHERE gm.group_id = 'grp' || substr(md5('module.relation_writers'), 1, 17)
   AND NOT EXISTS (
         SELECT 1 FROM kacho_iam.relation_fact f
          WHERE f.object_type = 'group' AND f.object_id = gm.group_id
            AND f.relation = 'member'
            AND f.subject = 'service_account:' || gm.member_id);

-- +goose StatementEnd
-- +goose StatementBegin

-- ── 4. Сама выдача: системная, на кластере, формой отношения ─────────────────
--
-- Идентификатор выводится ТЕМ ЖЕ выражением, что и у прочих системных выдач
-- (миграция 893002): повторное обратное заполнение попадёт в конфликт, а не
-- заведёт второй выдачи об одном предмете.
INSERT INTO kacho_iam.access_bindings (
    id, subject_type, subject_id, role_id, granted_relation, is_system,
    resource_type, resource_id, status, deletion_protection, granted_by_user_id)
VALUES (
    'acb' || substr(md5('system-grant:group:'
                        || ('grp' || substr(md5('module.relation_writers'), 1, 17))
                        || '#member:fga_writer:cluster:cluster_kacho_root'), 1, 17),
    'group', 'grp' || substr(md5('module.relation_writers'), 1, 17),
    NULL, 'fga_writer', true,
    'cluster', 'cluster_kacho_root', 'ACTIVE', true, '')
ON CONFLICT DO NOTHING;

-- +goose StatementEnd
-- +goose StatementBegin

-- Дочерняя строка субъекта — без неё субъект не виден ни перечислению, ни
-- проекции ответа.
INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
SELECT b.id, b.subject_type, b.subject_id, 0
  FROM kacho_iam.access_bindings b
 WHERE b.is_system AND b.granted_relation = 'fga_writer'
ON CONFLICT DO NOTHING;

-- +goose StatementEnd
-- +goose StatementBegin

-- ── 5. Реестр выданного ─────────────────────────────────────────────────────
--
-- Отзыв повторяет РЕЕСТР того, что выдача выдала, а не пересчёт по роли; у
-- выдачи без роли пересчитывать нечего, поэтому пустой реестр означал бы отзыв,
-- который не отзывает: строка выдачи исчезла, доступ остался. Ровно этот класс
-- задача и закрывает, поэтому строка реестра — часть переезда, а не украшение.
INSERT INTO kacho_iam.access_binding_emitted_tuples (binding_id, fga_user, relation, object, source)
SELECT b.id,
       'group:' || b.subject_id || '#member',
       b.granted_relation,
       b.resource_type || ':' || b.resource_id,
       'binding'
  FROM kacho_iam.access_bindings b
 WHERE b.is_system AND b.granted_relation = 'fga_writer'
ON CONFLICT DO NOTHING;

-- +goose StatementEnd
-- +goose StatementBegin

-- ── 6. Материализация выдачи ────────────────────────────────────────────────
INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
SELECT 'fga.tuple.write',
       jsonb_build_object(
         'user',     'group:' || ('grp' || substr(md5('module.relation_writers'), 1, 17)) || '#member',
         'relation', 'fga_writer',
         'object',   'cluster:cluster_kacho_root'),
       now()
 WHERE NOT EXISTS (
         SELECT 1 FROM kacho_iam.relation_fact f
          WHERE f.object_type = 'cluster' AND f.object_id = 'cluster_kacho_root'
            AND f.relation = 'fga_writer'
            AND f.subject = 'group:' || ('grp' || substr(md5('module.relation_writers'), 1, 17)) || '#member');

-- +goose StatementEnd
-- +goose StatementBegin

-- ── 7. Снятие прежнего основания ────────────────────────────────────────────
--
-- Снимается ПОСЛЕДНИМ и через тот же журнал: иначе состав группы (п.2) читать
-- было бы неоткуда. Оставить прежнее основание рядом с новым нельзя — два
-- действующих основания об одном предмете расходятся молча, и отзыв кластерной
-- выдачи оставил бы работающим то, которое отозвать нечем.
INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
SELECT 'fga.tuple.delete',
       jsonb_build_object(
         'user',     f.subject,
         'relation', f.relation,
         'object',   f.object_type || ':' || f.object_id),
       now()
  FROM kacho_iam.relation_fact f
 WHERE f.object_type = 'iam_fgaproxy';

-- +goose StatementEnd

-- +goose Down
--
-- ЧЕМ ОБРАТНЫЙ ХОД ОГРАНИЧЕН — СКАЗАНО, А НЕ УМОЛЧАНО.
--
-- Он возвращает прежнее основание на якорь `iam_fgaproxy:system`, тип которого
-- ЭТИМ ЖЕ изменением снят из модели. Значит откат СХЕМЫ в отрыве от отката КОДА
-- даёт состояние, в котором факт есть, а типа нет, и вопрос о праве отвечает
-- отказом: модель — часть кода и откатывается вместе с ним. Порядок отката
-- здесь тот же, что у всякой миграции, меняющей контракт: сперва код, потом
-- схема.
--
-- Обратный ход НЕ ПРОЙДЕН НИ ОДНОЙ ПРОБОЙ — это отмечено как непроверенное, а
-- не как исправное. Ближайшие пробы отката (`TestMigration0010_…DownReverts`,
-- `TestMigration0014_…DownReverts`) гоняют цикл до версий 9 и 13 и через эту
-- миграцию проходят, но утверждают они СВОЙ предмет — что посев 0009/0044/0057
-- не отредактирован, — а не восстановление права. То есть цепь отката
-- исполняется, а её исход здесь никем не проверяется.

-- +goose StatementBegin

-- Возврат прежнего основания: без факта модуль остался бы без права.
INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
SELECT 'fga.tuple.write',
       jsonb_build_object(
         'user',     'service_account:' || gm.member_id,
         'relation', 'fga_writer',
         'object',   'iam_fgaproxy:system'),
       now()
  FROM kacho_iam.group_members gm
 WHERE gm.group_id = 'grp' || substr(md5('module.relation_writers'), 1, 17);

-- +goose StatementEnd
-- +goose StatementBegin

INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
VALUES (
  'fga.tuple.delete',
  jsonb_build_object(
    'user',     'group:' || ('grp' || substr(md5('module.relation_writers'), 1, 17)) || '#member',
    'relation', 'fga_writer',
    'object',   'cluster:cluster_kacho_root'),
  now());

-- +goose StatementEnd
-- +goose StatementBegin

INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
SELECT 'fga.tuple.delete',
       jsonb_build_object(
         'user',     'service_account:' || gm.member_id,
         'relation', 'member',
         'object',   'group:' || gm.group_id),
       now()
  FROM kacho_iam.group_members gm
 WHERE gm.group_id = 'grp' || substr(md5('module.relation_writers'), 1, 17);

-- +goose StatementEnd
-- +goose StatementBegin

DELETE FROM kacho_iam.access_binding_emitted_tuples
 WHERE binding_id IN (
   SELECT id FROM kacho_iam.access_bindings
    WHERE is_system AND granted_relation = 'fga_writer');

-- +goose StatementEnd
-- +goose StatementBegin

DELETE FROM kacho_iam.access_binding_subjects
 WHERE binding_id IN (
   SELECT id FROM kacho_iam.access_bindings
    WHERE is_system AND granted_relation = 'fga_writer');

-- +goose StatementEnd
-- +goose StatementBegin

DELETE FROM kacho_iam.access_bindings
 WHERE is_system AND granted_relation = 'fga_writer';

-- +goose StatementEnd
-- +goose StatementBegin

DELETE FROM kacho_iam.group_members
 WHERE group_id = 'grp' || substr(md5('module.relation_writers'), 1, 17);

-- +goose StatementEnd
-- +goose StatementBegin

DELETE FROM kacho_iam.groups
 WHERE id = 'grp' || substr(md5('module.relation_writers'), 1, 17);

-- +goose StatementEnd
