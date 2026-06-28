# kacho-iam — ER-диаграмма (schema `kacho_iam`)

Все FK / UNIQUE / CHECK / партиальные индексы / триггеры определены в миграциях
`internal/migrations/` (базовая — `0001_initial.sql`); они — источник истины
схемы. Здесь — обзорная диаграмма и заметки по нетривиальным связям.

```mermaid
erDiagram
    USERS ||--o{ ACCOUNTS : "owns (RESTRICT)"
    ACCOUNTS ||--o{ PROJECTS : "contains (RESTRICT)"
    ACCOUNTS ||--o{ SERVICE_ACCOUNTS : "owns (RESTRICT)"
    ACCOUNTS ||--o{ GROUPS : "owns (RESTRICT)"
    ACCOUNTS ||--o{ ROLES : "owns custom (RESTRICT)"
    GROUPS ||--o{ GROUP_MEMBERS : "contains (CASCADE)"
    USERS ||..o{ GROUP_MEMBERS : "trigger ref"
    SERVICE_ACCOUNTS ||..o{ GROUP_MEMBERS : "trigger ref"
    ROLES ||--o{ ACCESS_BINDINGS : "grants (RESTRICT)"
    USERS ||..o{ ACCESS_BINDINGS : "subject (soft ref)"
    SERVICE_ACCOUNTS ||..o{ ACCESS_BINDINGS : "subject (soft ref)"
    GROUPS ||..o{ ACCESS_BINDINGS : "subject (soft ref)"
```

## Notes

- `group_members.member_id` — без FK на `users.id`/`service_accounts.id`
  (Postgres FK не поддерживает альтернативную ссылку). Целостность —
  через триггер `group_members_member_exists_trg`
  (BEFORE INSERT/UPDATE → EXISTS-check в соответствующей таблице).

- `access_bindings.subject_id` / `resource_id` — без FK (subject полиморфен;
  resource — cross-service / cross-DB, database-per-service — FK через границу
  сервиса невозможен). Целостность — soft (use-case sync-validate + graceful
  dangling-ref на чтении).

- `accounts.owner_user_id` → `users.id` ON DELETE **RESTRICT** — User'а,
  владеющего Account'ами, удалить нельзя.

- `operations` (corelib pattern + IAM-extension principal_* полей) — для
  всех LRO мутаций (Create/Update/Delete/Move/AddMember/RemoveMember).
