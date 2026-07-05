-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0045_registry_sa_rules.sql — backfill the rules[] policy of the kacho-registry
-- module-SA backing role.
--
-- Под rules-model каждая system-роль обязана нести rules[] (authored policy —
-- источник истины политики роли). Миграция 0031 пересеяла rules[] для всех
-- system-ролей, существовавших на тот момент, включая SEC-C module-SA роли
-- (module.vpc_sa / compute_sa / nlb_sa / vpc_operator_sa / api_gateway_sa).
-- Роль module.registry_sa заведена позже (миграция 0044) уже с legacy
-- permissions=['iam.projects.*.get'] и пустым rules[], поэтому её reseed из 0031
-- не затронул — она осталась единственной system-ролью без rules[].
--
-- Приводим её к rules-форме, эквивалентной module.api_gateway_sa (тот же least-priv
-- catalog — только iam.projects.*.get, проверка существования projectId на
-- Registry.Create). Форма — scalar `module` (актуальная после 0033); rule
-- {module:iam, resources:[projects], verbs:[get]} → tier viewer, что совпадает с
-- tier legacy-permission iam.projects.*.get (tier-parity сохраняется).
--
-- Idempotent: UPDATE ключуется по детерминированному id роли; повторный прогон
-- пишет те же rules (no-op). Если роль отсутствует — 0 строк, тоже no-op.
-- permissions[] не трогаем (backs FGA emission); строку не удаляем — access не
-- рвётся (FK-child AccessBinding из 0044 остаётся).

-- +goose Up
-- +goose StatementBegin

UPDATE kacho_iam.roles
   SET rules = '[{"module":"iam","resources":["projects"],"verbs":["get"]}]'::jsonb
 WHERE id = 'rol' || substr(md5('module.registry_sa'), 1, 17);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Возврат к состоянию после 0044: legacy permissions-only (пустой rules[]).
UPDATE kacho_iam.roles
   SET rules = '[]'::jsonb
 WHERE id = 'rol' || substr(md5('module.registry_sa'), 1, 17);

-- +goose StatementEnd
