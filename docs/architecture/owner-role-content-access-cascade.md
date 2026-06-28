# owner-роль и доступ к содержимому account'а — per-object, не каскад

By-design запись: by-design решение фиксируется в `docs/architecture/`, а не как
GitHub-issue. Фиксирует, **как именно** системная роль `owner` достает доступ к
содержимому своего account'а в explicit-RBAC-модели.

> Полная модель — [`explicit-rbac-model.md`](explicit-rbac-model.md). Здесь — узкий
> разбор одного решения: owner = per-object forward-materialization (а не
> hierarchy-каскад). Имя файла («…-cascade») историческое — по факту каскада нет.

## Что делает owner

`owner` (`is_system=true`, cluster-scoped) — wildcard-роль:

```json
rules       = [{ "module": "*", "resources": ["*"], "verbs": ["*"] }]
permissions = ["*.*.*.*"]   // deprecated-проекция, не источник смысла
```

На `Account.Create` сервис co-commit'ит `AccessBinding(subject=creator,
role=owner, scope=ACCOUNT:<A>, deletion_protection=true)` в той же writer-tx, что
и сам account. Дальше доступ материализует reconciler — единственный путь.

## Как owner достает содержимое: per-object разворачивание wildcard

В границе **ACCOUNT** (bounded scope) wildcard-правило `*.*.*`
**разворачивается per-object**: reconciler перечисляет все материализуемые типы
внутри account'а и эмитирует на каждый объект прямые `v_*` + `admin` tuple.

- На момент `Account.Create` account пуст → материализуется только self-tuple на
  `account:<A>` (verb-bearing self + tier `admin` как write-authz-якорь).
- Содержимое досоздается **forward**: на Create каждого ресурса в account'е
  reconciler досоздает owner-tuple на этот ресурс. Owner не протухает на
  ресурсах, появившихся после owner-binding.

Так каждый факт доступа owner — **явный tuple**, который можно перечислить,
объяснить (`ExpandAccess`) и снять (revoke по сохраненному ledger при снятии
гранта). Никакого вычисляемого `… from account`-каскада в семантике доступа нет —
он удален из FGA-модели (плоский индекс).

## Почему именно per-object (а не каскад)

Каскад `admin from account → admin from project → admin from <leaf>` был трудно
аудируемым: «почему у owner есть доступ» складывалось из нескольких вычисляемых
правил. Явные per-object tuple дают аудируемость и предсказуемость — ценой
бóльшего числа строк ledger, но **конечного и явного** (граница — именно ACCOUNT,
а не весь кластер).

## Граница: ACCOUNT, не CLUSTER

owner всегда биндится **@ ACCOUNT**, поэтому per-object набор ограничен одним
account'ом. На границе **CLUSTER** тот же wildcard НЕ разворачивается per-object
(это был бы неограниченный churn на каждый Create в кластере) — cluster-wide
super-grant обслуживает плоский short-circuit (см. cluster super-admin в
[`explicit-rbac-model.md`](explicit-rbac-model.md)). owner и cluster-admin несут
одинаковую `*.*.*`-форму, но различаются именно границей: owner @ ACCOUNT →
per-object; cluster-admin @ CLUSTER → short-circuit.

## Изоляция между account'ами

owner account'а A материализуется **только** на объекты внутри A. На объект
другого account'а B owner A не получает ни одного tuple — граница ACCOUNT строго
ограничивает разворачивание.

## Снятие защиты

owner-auto-binding защищен `deletion_protection=true`. Чтобы его удалить — сначала
`Update(update_mask=["deletion_protection"], deletion_protection=false)`, затем
`Delete`; revoke снимает все per-object owner-tuple по сохраненному ledger в той же
writer-tx.
