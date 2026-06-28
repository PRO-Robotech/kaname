# kacho-iam — миграции

Schema `kacho_iam`. На текущий момент 24 goose-миграции
(`0001_initial.sql` .. `0024_*.sql`), последовательно создающие:

- core resource model (`operations`, `users`, `accounts`, `projects`,
  `service_accounts`, `groups`, `group_members`, `roles`, `access_bindings`)
  + default-roles seed (12 system-ролей с детерминированными id);
- governance расширения (`access_bindings_jit_eligibility`, `_jit_pending`,
  `break_glass_*`);
- federation / identity (`oidc_jwks_keys`, `federation_*`, `scim_*`,
  `dpop_replay_jti`);
- outbox-cluster (`fga_outbox`, `subject_change_outbox`, `caep_outbox`,
  `audit_outbox`).

CHECK / FK / UNIQUE / partial UNIQUE / триггеры inline в соответствующих
миграциях. Helper-функции: `kacho_labels_valid(jsonb)`,
`iam_permissions_valid(jsonb)`, триггер `group_members_member_exists_trg`.

Squash в единый `0001_initial.sql` baseline запланирован в Wave M
рефакторинга `KAC-193` (после Wave D evgeniy-compliance pass).

## Запуск

`make migrate-up` (требует `KACHO_IAM_DB_PASSWORD=...`).

## Запреты

- НЕ редактировать примененную миграцию (workspace `CLAUDE.md` запрет #5) —
  только новая миграция с инкрементным номером (следующий — `0025_*`).
- `make sync-migrations` — no-op: общая `operations` встроена в baseline под
  схемой `kacho_iam` (re-копирование common-файла создало бы конфликтующий
  unqualified `public.operations`).
