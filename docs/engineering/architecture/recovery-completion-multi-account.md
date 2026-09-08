# Recovery completion vs the multi-account uniqueness schema

By-design note for `InternalUserService.OnRecoveryCompleted`. Resolves a
discrepancy between an early design assumption and the actual uniqueness schema.

## The discrepancy

An early design reasoned about which multi-account states a single Kratos identity
(`external_id`) can occupy by citing only the **per-Account** uniqueness:

```
users_account_external_id_unique  UNIQUE (account_id, external_id) WHERE external_id <> ''
```

It **missed** migration `0011_users_drop_global_email_uniqueness.sql`, which adds a
stricter **GLOBAL** partial unique index:

```sql
CREATE UNIQUE INDEX users_active_external_id_uniq
    ON kaname.users (external_id)
    WHERE invite_status = 'ACTIVE' AND external_id <> '';
```

## What the global guard actually allows

`users_active_external_id_uniq` enforces **at most one ACTIVE row per `external_id`,
globally** — but it does **not** restrict BLOCKED (or PENDING) rows. So:

| Multi-account state for one `external_id`           | Reachable? | Why |
|------------------------------------------------------|------------|-----|
| Two **ACTIVE** rows (different Accounts)             | **No**     | `users_active_external_id_uniq` forbids it (the "two-ACTIVE" premise is **unreachable**). |
| One **ACTIVE** (Account A) + one **BLOCKED** (Account B) | **Yes**    | BLOCKED rows are not covered by the partial index — both rows can coexist. |
| One **BLOCKED** + one **PENDING** (`external_id=''`) | **Yes**    | PENDING carries `external_id=''` (CHECK `users_invite_status_consistency`); not matched by `external_id`. |

So the "two-ACTIVE" premise is **impossible**. The genuinely reachable
multi-account collision case is **BLOCKED + ACTIVE across Accounts**.

## How recovery handles BLOCKED + ACTIVE across Accounts

Recovery matches the identity's ACTIVE/BLOCKED rows by `(external_id, email)` and works
on both statuses in one writer-tx — the matched set is `recoveryStatuses` in
`internal/apps/kaname/api/user/internal_on_recovery.go`. Re-enabling a BLOCKED row beside
an already-ACTIVE sibling would collide with `users_active_external_id_uniq` and raise
SQLSTATE `23505`.

> [!warning] Ниже здесь был описан механизм, которого в дереве НЕТ — раздел снят, а не поправлен
> Прежняя редакция описывала пошаговую схему с точками сохранения внутри транзакции:
> постановку точки перед каждым повторным включением строки, откат к ней на коллизии
> глобального индекса и продолжение цикла, плюс примитивы этой схемы в pg-адаптере и
> проверку имени точки. Замер на 2026-08-06, предикат назван: поиск по всем `*.go`
> сервиса даёт **ноль** вхождений и у примитива точки сохранения, и у метода повторного
> включения, и у проверки имени; единственное совпадение слова «savepoint» во всём
> сервисе — в тесте другого ресурса. То есть документ описывал не «как сделано», а
> замысел, и делал это в настоящем времени.
>
> Имена не воспроизводятся: в обратных кавычках они читаются как живые координаты, и
> следующий контрибьютор пойдёт их искать (а найдя пустоту — «починит» код под неверный
> документ; ровно тот сценарий, от которого предостерегает правило о правдивости
> комментариев).
>
> Что из прежнего раздела **остаётся верным** и потому сохранено выше: разбор схемы
> уникальности и недостижимость состояния «две ACTIVE-строки». Это утверждения о миграции
> `0011_users_drop_global_email_uniqueness.sql`, и они проверены по ней.

> [!warning] Пара BLOCKED + ACTIVE в разных аккаунтах СНЯТА КЛЮЧОМ — форма больше не достижима
> Здесь стояло, что такая пара достижима, и это было верно, пока уникальность была
> ПАРНОЙ с аккаунтом: у человека была строка на каждый аккаунт, и состояния этих строк
> расходились.
>
> Миграция `20260823050000_users_identity_uniqueness_goes_global.sql` (задачи kacho#470 /
> kacho#981) сделала ключи глобальными: `users_identity_email_uniq` по адресу и
> `users_identity_external_id_uniq` по внешнему субъекту. У человека одна строка на всю
> платформу, значит и состояние у него одно — блокировка есть свойство ЛИЧНОСТИ, а не
> членства (решение владельца, вопрос В-8 приёмки IAM-ID-1). Принадлежность аккаунтам
> выражается строками `memberships`, которых может быть несколько, и состояния они не
> несут.
>
> **Что от этого раздела остаётся в силе:** восстановление доступа НЕ снимает
> административный запрет, и отсечка ставится на строку личности. Это и утверждает
> названная ниже проба — её многоаккаунтность теперь выражена двумя ЧЛЕНСТВАМИ одной
> строки, а не двумя строками. Имя пробы сохранено намеренно, чтобы ссылка отсюда не
> повисла.

## Tests

- `internal/repo/kaname/pg/recovery_completions_integration_test.go` —
  `TestOnRecoveryCompleted_S09_MultiAccountIdentity_RevokeAll` (канонический случай
  BLOCKED + PENDING-сосед), плюс сценарии S01-S05 и S07 в том же файле; конкурентность
  покрыта `TestOnRecoveryCompleted_S05_DuplicateJTI_IdempotentNoop`.
- `internal/repo/kaname/pg/recovery_keeps_block_integration_test.go` —
  `TestOnRecoveryCompleted_BlockedStaysBlocked` / `_ActiveStaysActive`.

> [!warning] Здесь были перечислены ещё две пробы — их нет
> Прежняя редакция называла пробу на коллизию BLOCKED + ACTIVE между аккаунтами и
> отдельный файл с пробой на гонку повторного включения. Поиск по имени функции и по
> имени файла даёт ноль. **Проба, которой нет, хуже отсутствующей**: она занимает слот в
> перечне покрытия и создаёт уверенность, которой нет. Это открытый долг — заявленный
> инвариант (при коллизии одна строка остаётся заблокированной, а отзыв сессий и запись
> аудита всё равно фиксируются) **не проверяется ничем**, и записан он здесь именно как
> долг с числом, а не как зелёная строка перечня.
