-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 893002_built_in_access_moves_onto_the_grant_surface — встроенный доступ
-- платформы становится СИСТЕМНЫМИ ВЫДАЧАМИ, и заводится та, которой не было.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧАСТЬ 1. ОБРАТНОЕ ЗАПОЛНЕНИЕ
--
-- Каждый действующий прямой факт на ЯРУСЕ ИЕРАРХИИ получает парную системную
-- выдачу. Строки читаются ИЗ САМОГО ФАКТА, а не выписываются: перечень посевов
-- рос девятью миграциями и продолжит расти, а выписанный список разошёлся бы с
-- деревом молча.
--
-- Факт при этом НЕ переэмитится: он уже произведён тем же журналом, из которого
-- его производила бы выдача, и повторная эмиссия добавила бы строк журнала, не
-- изменив состояния. Инвариант «факт производится из выдачи» действует ВПЕРЁД:
-- создание выдачи кладёт в журнал запись, отзыв — снятие.
--
-- Отношения-ГЛАГОЛЫ (`v_*`) исключены: их выводит форма роли из своих правил, и
-- выдача отношения на них не заводится (проекция журнала их и не переносит).
-- ЧЛЕНСТВО (`member`) исключено: это состав группы, у него своя поверхность.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧАСТЬ 2. ПУБЛИЧНОЕ ЧТЕНИЕ СПРАВОЧНИКОВ — ВЫДАЧА, КОТОРОЙ НЕ БЫЛО
--
-- Модель прав объявляет на кластере отношение `viewer` с подстановочным
-- субъектом: глобальный справочник размещения (регионы, зоны, типы машин, типы
-- дисков) обязан читать всякий аутентифицированный арендатор. Производителей у
-- этого факта не было НИ ОДНОГО — отношение объявлено и не выполняется никем,
-- поэтому чтения справочников пришлось объявить освобождением от проверки.
--
-- Здесь оно заводится тем же способом, что и всё остальное: системной выдачей.
-- Следствия ровно два, и оба — предмет задачи: доступ ВИДЕН перечислением выдач
-- и ОТЗЫВАЕТСЯ штатно (закрыть публичность справочника становится операцией
-- администратора, а не выкаткой).
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ЗАЩИТА ОТ УДАЛЕНИЯ ВКЛЮЧЕНА
--
-- Случайное снятие системной выдачи — это отказ платформы: край перестаёт
-- читать личности, домены перестают читать пределы, арендатор перестаёт видеть
-- справочник. Отзыв остаётся возможным и штатным — снять защиту правкой, затем
-- удалить, — но требует двух осознанных действий, а не одного.
--
-- ПОЧЕМУ «КТО ВЫДАЛ» ПУСТО. Выдал не человек, а платформа, и признак `is_system`
-- отвечает на этот вопрос точнее, чем любая подставленная учётка. Приписать
-- выдачу якорному пользователю системного аккаунта значило бы записать в аудит
-- действие, которого он не совершал.

-- +goose Up
-- +goose StatementBegin

-- ── 1. Действующие факты ярусов → системные выдачи ───────────────────────────
INSERT INTO kacho_iam.access_bindings (
    id, subject_type, subject_id, role_id, granted_relation, is_system,
    resource_type, resource_id, status, deletion_protection, granted_by_user_id)
SELECT
    'acb' || substr(md5('system-grant:' || f.subject || ':' || f.relation
                        || ':' || f.object_type || ':' || f.object_id), 1, 17),
    split_part(f.subject, ':', 1),
    -- Идентификатор субъекта: всё после первого двоеточия, без хвоста членства.
    -- Хвост принадлежит ФОРМЕ ИМЕНИ субъекта в факте, а не его идентификатору, и
    -- восстанавливается той же формой при чтении.
    split_part(split_part(f.subject, ':', 2), '#', 1),
    NULL,
    f.relation,
    true,
    f.object_type,
    f.object_id,
    'ACTIVE',
    true,
    ''
  FROM kacho_iam.relation_fact f
 WHERE f.object_type IN ('cluster', 'account', 'project')
   AND f.relation <> 'member'
   AND f.relation NOT LIKE 'v\_%'
   AND split_part(f.subject, ':', 1) IN ('user', 'service_account', 'group')
   AND split_part(split_part(f.subject, ':', 2), '#', 1) <> ''
ON CONFLICT DO NOTHING;

-- +goose StatementEnd
-- +goose StatementBegin

-- Дочерняя строка субъекта — та же, что заводит любая выдача: без неё субъект не
-- виден ни перечислению, ни проекции ответа.
INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
SELECT b.id, b.subject_type, b.subject_id, 0
  FROM kacho_iam.access_bindings b
 WHERE b.is_system
ON CONFLICT DO NOTHING;

-- +goose StatementEnd
-- +goose StatementBegin

-- ── 2. Публичное чтение справочников ─────────────────────────────────────────
INSERT INTO kacho_iam.access_bindings (
    id, subject_type, subject_id, role_id, granted_relation, is_system,
    resource_type, resource_id, status, deletion_protection, granted_by_user_id)
VALUES (
    'acb' || substr(md5('system-grant:user:*:viewer:cluster:cluster_kacho_root'), 1, 17),
    'user', '*', NULL, 'viewer', true,
    'cluster', 'cluster_kacho_root', 'ACTIVE', true, '')
ON CONFLICT DO NOTHING;

-- +goose StatementEnd
-- +goose StatementBegin

INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
VALUES (
    'acb' || substr(md5('system-grant:user:*:viewer:cluster:cluster_kacho_root'), 1, 17),
    'user', '*', 0)
ON CONFLICT DO NOTHING;

-- +goose StatementEnd
-- +goose StatementBegin

-- Материализация публичного чтения — через журнал намерений, тем же путём, каким
-- материализуется любая выдача. Проекция журнала кладёт прямой факт в этом же
-- коммите.
INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
VALUES (
    'fga.tuple.write',
    jsonb_build_object(
        'user',     'user:*',
        'relation', 'viewer',
        'object',   'cluster:cluster_kacho_root'),
    now())
ON CONFLICT DO NOTHING;

-- +goose StatementEnd

-- +goose StatementBegin

-- ── 3. Реестр выданных кортежей ──────────────────────────────────────────────
--
-- Отзыв выдачи повторяет НЕ пересчёт по текущей роли, а РЕЕСТР того, что эта
-- выдача выдала: роль между выдачей и отзывом могла измениться, и пересчёт снял
-- бы не то, что выдавалось. Системная выдача обязана нести свою строку реестра —
-- иначе отзыв не эмитировал бы ничего, факт пережил бы выдачу, и «отозвано»
-- означало бы «выдача исчезла, доступ остался». Это ровно тот класс, ради
-- которого задача и заведена, поэтому строка реестра — часть обратного
-- заполнения, а не украшение.
INSERT INTO kacho_iam.access_binding_emitted_tuples (binding_id, fga_user, relation, object, source)
SELECT b.id,
       CASE b.subject_type
         WHEN 'service_account' THEN 'service_account:' || b.subject_id
         WHEN 'group'           THEN 'group:' || b.subject_id || '#member'
         ELSE                        'user:' || b.subject_id
       END,
       b.granted_relation,
       b.resource_type || ':' || b.resource_id,
       'binding'
  FROM kacho_iam.access_bindings b
 WHERE b.is_system AND b.granted_relation <> ''
ON CONFLICT DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM kacho_iam.fga_outbox
 WHERE payload->>'user'     = 'user:*'
   AND payload->>'relation' = 'viewer'
   AND payload->>'object'   = 'cluster:cluster_kacho_root';

-- +goose StatementEnd
-- +goose StatementBegin

DELETE FROM kacho_iam.relation_fact
 WHERE object_type = 'cluster'
   AND object_id   = 'cluster_kacho_root'
   AND relation    = 'viewer'
   AND subject     = 'user:*';

-- +goose StatementEnd
-- +goose StatementBegin

DELETE FROM kacho_iam.access_bindings WHERE is_system;

-- +goose StatementEnd
