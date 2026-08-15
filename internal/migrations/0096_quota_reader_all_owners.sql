-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- Читателями пределов становятся ВСЕ владельцы считаемых видов, а не один vpc.
--
-- ПРЕДМЕТ. Миграция 0093 завела группу читателей пределов и включила в неё
-- единственную служебную учётку — vpc, потому что на тот момент считал только он.
-- Волна S3/S4 дала списание квоты ещё четырём доменам, но членства им не выдала:
-- каждая их мутация уходит материализовать учёт, зовёт `InternalLimitService.Resolve`
-- и получает отказ в правах.
--
-- ЧТО ЭТО ЗНАЧИЛО НА ПОДНЯТОМ СТЕНДЕ. Отказ в правах на пути материализации —
-- fail-closed по построению (пропустить мутацию, не установив предела, значит снять
-- контроль там, где это труднее всего заметить). Значит НИ ОДНА мутация этих
-- доменов не проходила: сквозной прогон nlb дал 748 упавших утверждений из 1806,
-- и все они — каскад от одного отказа, а не 748 разных дефектов.
--
-- ПОЧЕМУ ЭТО НЕ БЫЛО ВИДНО РАНЬШЕ. Каждая доменная линия проверяла себя пробами
-- уровня репозитория и юнитами: там резолв подставной и прав не спрашивает.
-- Право живёт в третьем месте — в модели прав iam, — и его отсутствие не роняет
-- ни сборку, ни пробы владельца. Это в точности класс «межсервисное намерение —
-- контракт ПРИНИМАЮЩЕЙ стороны, а не факт эмиссии» (`data-integrity.md`): эмиссия
-- была у всех четверых, право — только у одного.
--
-- ПОЧЕМУ ЧЕРЕЗ ГРУППУ, А НЕ ПЕРЕЧИСЛЕНИЕМ. Право получают пятеро, и состав будет
-- меняться с каждым новым доменом. Правило B18 (`data-integrity.md`): право, которое
-- получает больше одного принципала или чей состав может измениться, выдаётся
-- ГРУППЕ. Группа уже есть — 0093 её и завела; здесь добавляется только членство.

-- +goose Up
-- +goose StatementBegin

-- ── Членство в группе читателей пределов ────────────────────────────────────
--
-- Идентичности выводятся тем же выражением, что в 0093: `sva` + первые 17 знаков
-- хеша имени. Выписывать их литералами нельзя — разошлись бы с посевом молча.
INSERT INTO kacho_iam.group_members (group_id, member_type, member_id)
SELECT
  'grp' || substr(md5('module.quota_readers'), 1, 17),
  'service_account',
  'sva' || substr(md5(svc), 1, 17)
FROM (VALUES
  ('kacho-nlb'),
  ('kacho-registry'),
  ('kacho-storage'),
  ('kacho-compute')
) AS owners(svc)
ON CONFLICT DO NOTHING;

-- +goose StatementEnd
-- +goose StatementBegin

-- ── Кортежи членства ────────────────────────────────────────────────────────
--
-- Через `fga_outbox`: внешнее хранилище прав не может атомарно закоммититься с
-- этой транзакцией, поэтому членство эмитится намерением, а дренаж применяет его
-- идемпотентно (at-least-once). Выдача самого отношения `quota_reader` группе уже
-- сделана в 0093 и здесь не повторяется — иначе получилось бы два места об одном.
INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
SELECT
  'fga.tuple.write',
  jsonb_build_object(
    'user',     'service_account:' || ('sva' || substr(md5(svc), 1, 17)),
    'relation', 'member',
    'object',   'group:' || ('grp' || substr(md5('module.quota_readers'), 1, 17))),
  now()
FROM (VALUES
  ('kacho-nlb'),
  ('kacho-registry'),
  ('kacho-storage'),
  ('kacho-compute')
) AS owners(svc)
ON CONFLICT DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Снятие членства. Само отношение группы не трогается: его завела 0093, и её
-- откат — её ответственность.
DELETE FROM kacho_iam.group_members
 WHERE group_id = 'grp' || substr(md5('module.quota_readers'), 1, 17)
   AND member_type = 'service_account'
   AND member_id IN (
     'sva' || substr(md5('kacho-nlb'), 1, 17),
     'sva' || substr(md5('kacho-registry'), 1, 17),
     'sva' || substr(md5('kacho-storage'), 1, 17),
     'sva' || substr(md5('kacho-compute'), 1, 17)
   );

-- +goose StatementEnd
-- +goose StatementBegin

INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
SELECT
  'fga.tuple.delete',
  jsonb_build_object(
    'user',     'service_account:' || ('sva' || substr(md5(svc), 1, 17)),
    'relation', 'member',
    'object',   'group:' || ('grp' || substr(md5('module.quota_readers'), 1, 17))),
  now()
FROM (VALUES
  ('kacho-nlb'),
  ('kacho-registry'),
  ('kacho-storage'),
  ('kacho-compute')
) AS owners(svc);

-- +goose StatementEnd
