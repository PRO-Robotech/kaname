-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0093_quota_reader_group.sql — кто вправе читать действующие потолки арендатора.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ
--
-- `InternalLimitService.Resolve` / `ListChangedSince` (issue #291) читают сервисы,
-- ВЛАДЕЮЩИЕ считаемыми типами ресурсов: им нужно знать действующий потолок и его
-- изменения, чтобы держать у себя проекцию и списывать по ней. Право названо
-- отдельным отношением `quota_reader` на кластерном объекте — не `system_viewer`
-- (это вся кластерная поверхность чтения, выдача много шире способности) и не
-- `viewer` (он НАМЕРЕННО выполняется подстановкой `user:*` — глобальный
-- справочник размещения обязан читаться каждым арендатором, поэтому проверка
-- против него отвечала бы «да» всем и выглядела бы при этом гейтом).
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ГРУППА, А НЕ ПЕРЕЧИСЛЕНИЕ УЧЁТОК
--
-- Получателей будет больше одного, и состав будет меняться: сегодня потолки
-- считает владелец сети, следом — владельцы хранилища, балансировщика, реестра и
-- машин. Право, чей состав получателей меняется, выдаётся ГРУППЕ, а учётки
-- добавляются в неё (data-integrity.md B18): снять одного из группы — одна строка
-- членства, снять одного из перечисления — снятие кортежей по всем объектам.
--
-- Сегодня в группе ОДНА учётка, и это не довод против группы: цена формы платится
-- один раз здесь, а не при каждом следующем владельце.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ДВА КОРТЕЖА, А НЕ ОДИН
--
-- Членство в группе НЕ выводится хранилищем прав из строки `group_members` само —
-- оно материализуется кортежем (`group:<gid>#member@service_account:<sva>`);
-- прецедент ровно этого посева — миграция 0029. Второй кортеж — сама выдача
-- (`cluster:<root>#quota_reader@group:<gid>#member`). Пропусти любой из двух — и
-- проверка отвечала бы отказом при верной на вид строке в базе.

-- +goose Up
-- +goose StatementBegin

-- ── 1. Группа читателей потолков (в системном аккаунте, что и модульные учётки) ──
INSERT INTO kacho_iam.groups (id, account_id, name, description)
VALUES (
  'grp' || substr(md5('module.quota_readers'), 1, 17),
  'acc' || substr(md5('kacho-system'), 1, 17),
  'module-quota-readers',
  'Owner-service accounts allowed to read effective resource-count limits (issue #291)'
)
ON CONFLICT (id) DO NOTHING;

-- +goose StatementEnd
-- +goose StatementBegin

-- ── 2. Состав: владельцы считаемых типов ────────────────────────────────────
-- Сегодня это владелец сети — единственный, чьи виды входят в закрытый каталог
-- считаемых (`vpc.*`). Следующий владелец добавляется СТРОКОЙ СЮДА своей
-- миграцией; ни модель, ни выдача при этом не трогаются — ради этого группа и
-- заведена.
INSERT INTO kacho_iam.group_members (group_id, member_type, member_id)
VALUES (
  'grp' || substr(md5('module.quota_readers'), 1, 17),
  'service_account',
  'sva' || substr(md5('kacho-vpc'), 1, 17)
)
ON CONFLICT DO NOTHING;

-- +goose StatementEnd
-- +goose StatementBegin

-- ── 3. Кортежи: членство и сама выдача ──────────────────────────────────────
-- Через fga_outbox — дренаж применяет их к хранилищу прав идемпотентно.
INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at) VALUES
  ('fga.tuple.write',
   jsonb_build_object(
     'user',     'service_account:' || ('sva' || substr(md5('kacho-vpc'), 1, 17)),
     'relation', 'member',
     'object',   'group:' || ('grp' || substr(md5('module.quota_readers'), 1, 17))),
   now()),
  ('fga.tuple.write',
   jsonb_build_object(
     'user',     'group:' || ('grp' || substr(md5('module.quota_readers'), 1, 17)) || '#member',
     'relation', 'quota_reader',
     'object',   'cluster:cluster_kacho_root'),
   now())
ON CONFLICT DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM kacho_iam.fga_outbox
 WHERE payload->>'relation' = 'quota_reader'
   AND payload->>'object'   = 'cluster:cluster_kacho_root';

-- +goose StatementEnd
-- +goose StatementBegin

DELETE FROM kacho_iam.fga_outbox
 WHERE payload->>'relation' = 'member'
   AND payload->>'object'   = 'group:' || ('grp' || substr(md5('module.quota_readers'), 1, 17));

-- +goose StatementEnd
-- +goose StatementBegin

DELETE FROM kacho_iam.group_members
 WHERE group_id = 'grp' || substr(md5('module.quota_readers'), 1, 17);

-- +goose StatementEnd
-- +goose StatementBegin

DELETE FROM kacho_iam.groups
 WHERE id = 'grp' || substr(md5('module.quota_readers'), 1, 17);

-- +goose StatementEnd
