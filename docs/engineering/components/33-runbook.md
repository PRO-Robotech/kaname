# 33. Production Runbook

## Назначение

Реакция на типичные инциденты в production kacho-iam. Каждая запись
включает: симптом → быстрая диагностика → действия → escalation.

Карта listener'ов (чтобы быстро ориентироваться в портах):

| Порт | Назначение |
|------|------------|
| `:9090` | публичный gRPC (tenant-facing, TLS/JWT) |
| `:9091` | internal gRPC (service→service, mTLS): `InternalIAMService.Check`, fgaproxy `RegisterResource`, cluster-admin, session-revocations |
| `:9092` | iamhooks HTTP — Ory Hydra `token`/`refresh` + Ory Kratos `provision` хуки (cluster-internal) |
| `:9095` | Prometheus `/metrics` (cluster-internal) |

Readiness/liveness — TCP-проба на `:9090`.

## P1 — Авторизация полностью не работает

**Симптомы:**
- API calls (через api-gateway) возвращают `UNAVAILABLE`/`PERMISSION_DENIED` массово.
- Postgres `kacho_iam` недоступен или деградирует.

**Быстрая диагностика:**

```bash
# Pod alive?
kubectl -n kacho get pod -l app=kacho-iam

# DB reachable? (от корня репозитория)
make -C deploy psql SVC=iam   # либо nc -zv <db-host> 5432

# subject_change_outbox растет (pending = sent_at IS NULL)?
kubectl -n kacho exec deploy/postgres -- \
  psql -c "SELECT count(*) FROM kacho_iam.fga_outbox WHERE sent_at IS NULL;"

# Логи последние 5min.
kubectl -n kacho logs -l app=kacho-iam --since=5m | grep -E "ERROR|FATAL|authz|verdict"
```

**Действия:**

1. **DB down** → escalate DBA. Это **полный отказ авторизации**: вердикт
   складывается той же базой, поэтому недоступность `kacho_iam` означает
   fail-closed по всем доменам, а не только по мутациям iam. Разбор и цена —
   [`../architecture/failure-domains.md`](../architecture/failure-domains.md).
2. **Реплика для чтения отстаёт** → вердикт читает master; проверить, не
   переключён ли пул на реплику.
3. **kacho-iam OOM/crash** → `kubectl rollout restart deploy/kacho-iam`;
   проверить memory limits.
4. **subject_change_outbox backlog огромный** (>10k pending) — см. раздел ниже:
   drainer все подтянет, но grant→Check propagation временно нарушена.

**Escalation:** SRE on-call → IAM team.

## P2 — выдача есть, доступа нет

> [!note] До стадии S6 этот раздел назывался «дренаж журнала отстаёт» — предмета нет
> Прежняя редакция описывала отставание вывоза строк журнала во внешний движок:
> «грант уже в базе iam, но кортеж ещё не записан в движок». Ни движка, ни вывоза
> не существует — прямой факт складывается **той же транзакцией**, что и выдача,
> поэтому состояние «выдано, но не применено» невыразимо by construction.
>
> Симптом при этом остался и приходит теперь из двух других мест. Раздел переписан
> под них.

**Симптом:** пользователь получил выдачу, а вызов по-прежнему отвергается.

### Причина 1 — отстал кэш края (частая, самоисправляющаяся)

api-gateway кэширует срез прав субъекта; сброс идёт очередью
`kacho_iam.subject_change_outbox` (канал `kacho_iam_subject_outbox_added`) плюс
запасной опрос раз в 30 с. Пока сброс не доехал, край отвечает по старому срезу.

```bash
# Сколько pending и насколько стара самая старая.
kubectl -n kacho exec deploy/postgres -- psql -c "
SELECT count(*)                AS pending,
       now() - min(created_at) AS oldest_pending_age,
       max(last_error)         AS last_error
FROM kacho_iam.subject_change_outbox
WHERE sent_at IS NULL;
"

# Ошибки применения в логах.
kubectl -n kacho logs -l app=kacho-iam --since=10m | grep -E "subject_change"
```

**Действия:**

1. **Проверить, что дело в кэше** — спросить iam напрямую, минуя край:
   `AuthorizeService.Check` по внутреннему слушателю. Отвечает `allowed=true` —
   значит право есть и отстал именно кэш.
2. **Дренаж завис** (пропущен `NOTIFY`) → разбудить:
   ```bash
   kubectl -n kacho exec deploy/postgres -- psql -c "NOTIFY kacho_iam_subject_outbox_added;"
   ```
   Не помогает — `kubectl rollout restart deploy/kacho-iam` (дренаж переустановит
   `LISTEN` и догонит опросом на старте).
3. **Край недоступен для сброса** → `last_error` повторяется; проверить
   internal-порт api-gateway и mTLS-ребро.

### Причина 2 — намерение не стало фактом (редкая, не самоисправляющаяся)

Право не появляется и при обращении мимо кэша. Тогда сверяются журнал и его
проекция:

```bash
kubectl -n kacho exec deploy/postgres -- psql -c "
-- намерение записано?
SELECT id, event_type, payload, created_at
  FROM kacho_iam.fga_outbox
 WHERE payload::text LIKE '%<subject_id>%'
 ORDER BY id DESC LIMIT 10;
-- факт сложился?
SELECT * FROM kacho_iam.relation_fact
 WHERE subject = 'user:<subject_id>' LIMIT 20;
"
```

| Что видно | Что это значит | Что делать |
|---|---|---|
| строки нет ни в журнале, ни в проекции | намерение не эмитировано | чинить производителя (use-case выдачи), не проекцию |
| строка в журнале есть, в проекции нет | дефект триггера проекции | escalate IAM team; предмет — миграция `0098_relation_fact_follows_the_journal.sql` |
| обе строки есть, доступа нет | вопрос не к факту: смотреть выдачу роли, метки, членство | разбор — `AuthorizeService.ExpandRelations` на этом ресурсе |

`ExpandRelations` отвечает **плоским перечнем оснований** — из чего право
складывается сейчас. Пустой перечень при живой выдаче означает, что план вывода
не связал роль с глаголом: сверять `role_verb` и модель прав.


## P2 — Ory Hydra / Kratos hooks недоступны

AuthN-хуки слушают на cluster-internal HTTP `:9092`: Hydra `token`/`refresh`
(обогащение OAuth2-токена) и Kratos `provision` (registration/login →
`UpsertFromIdentity`: bootstrap Account/Project/AccessBinding нового identity
либо активация PENDING-invite). Если хуки падают — новые пользователи не
провижинятся, токены не обогащаются.

**Симптомы:**
- Новый пользователь логинится, но не видит свой Account/Project.
- Hydra/Kratos логи показывают 5xx с webhook-эндпоинта kacho-iam.

**Диагностика:**

```bash
# Хуки-листенер поднят?
kubectl -n kacho logs -l app=kacho-iam --since=10m | grep -E "iamhooks|provision|UpsertFromIdentity"

# Identity уже отзеркалена?
kubectl -n kacho exec deploy/postgres -- \
  psql -c "SELECT id, external_id, created_at FROM kacho_iam.users ORDER BY created_at DESC LIMIT 5;"
```

**Действия:**

1. **kacho-iam down/restarting** → хук-вызовы Hydra/Kratos падают;
   восстановить pod (`kubectl rollout restart deploy/kacho-iam`).
2. **HMAC/секрет хука разошелся** → провижн-хук отвергает запрос; сверить
   webhook-секрет на стороне Kratos/Hydra и в config kacho-iam.
3. **Provision прошел частично** → `UpsertFromIdentity` идемпотентен по
   `external_id` (Kratos/Hydra `sub`); повторный login досоздаст недостающее.
   Admin-tooling может вызвать тот же `InternalUserService.UpsertFromIdentity`
   напрямую на `:9091`.

## P2 — 401 / `unknown kid` на всех JWT

**Сначала главное: издателей ДВА, и `unknown kid` у каждого чинится по-своему.**
Слушатель `:9097` отдаёт две РАЗНЫЕ записи по двум РАЗНЫМ путям, и путать их
нельзя:

| запись | путь | чьи ключи | чинится |
|---|---|---|---|
| зеркало прежнего издателя | канонический well-known | **Hydra** — она издатель и подписант | на стороне Hydra |
| **наша запись** | `authn.token-signing.key-set-path` (умолчание `/.well-known/kacho/jwks.json`) | **ключница iam** — платформа чеканит свои токены сама (#897) | внутри iam |

Записи заведены раздельно намеренно. Объединить наборы в один документ было бы
дешевле и уничтожило бы ровно ту защиту, ради которой развязка «издатель →
источник набора» и существует: ключ одного издателя проверял бы токен,
объявляющий другого. Зеркало остаётся на своём прежнем пути до конца перехода —
его адрес объявлен у каждого сегодняшнего потребителя, и перенос сменил бы адрес
у всех разом.

**Отсюда первый вопрос при `unknown kid`: чей это токен?** Издателя видно в самом
токене; по нему выбирается запись, а по записи — сторона, на которой чинить.

Прежнее хранилище подписных ключей снято миграцией и не возвращается: приватную
половину не читал обратно никто, а запись в него удавалась — поэтому оно
выглядело исправным всю свою жизнь. Его отсутствие — норма, НЕ причина инцидента.
Отчёт о состоянии ключей снят с обслуживания вместе с ним (он отдавал пустой
набор и никем не звался).

**Симптомы:**
- api-gateway отдаёт 401 на все JWT; в логах валидации — `unknown kid` / signature mismatch.

**Диагностика:**

```bash
# 1. Что реально отдаёт Hydra (источник истины по kid'ам)?
kubectl -n kacho exec deploy/kacho-umbrella-hydra -- \
  wget -qO- http://127.0.0.1:4444/.well-known/jwks.json | jq '.keys[].kid'

# 2. Что отдаёт зеркало iam (:9097)? kid'ы обязаны СОВПАДАТЬ с п.1.
kubectl -n kacho exec deploy/kacho-iam -- \
  wget -qO- --no-check-certificate https://127.0.0.1:9097/.well-known/jwks.json | jq '.keys[].kid'
```

**Действия:**

1. **kid'ы в п.1 и п.2 совпадают, а gateway всё равно 401** → gateway кеширует
   JWKS; рестартнуть gateway-pod, чтобы сбросить кеш.
2. **Зеркало (п.2) отдаёт 502** → это fail-closed: Hydra недоступна/отдаёт не-200,
   а кеш холодный. Чинить Hydra; зеркало восстановится само (TTL 5m).
3. **Зеркало отдаёт наш kid** → регресс: наша запись просочилась в запись
   зеркала. Зеркало обязано быть дословной копией источника; наши ключи живут в
   ОТДЕЛЬНОЙ записи по своему пути, и для потребителя, пиннутого на прежнего
   издателя, наш kid не совпадёт никогда.
4. **Hydra недоступна** → токены прежнего издателя не выпускаются вовсе;
   восстановить Hydra, далее повторить логин.
5. **Наша запись пуста либо отвечает отказом** → это два РАЗНЫХ исхода, и они
   намеренно различимы: «источник не ответил» — повтор осмыслен; «ключей нет
   вовсе» — повтор не поможет, нужен ключ. Публикация идёт целиком либо никак:
   частичного набора не бывает, потому что набор с пропущенным ключом отвергает
   живые токены, ничем себя не выдавая.
6. **Токен нашего издателя отвергнут сразу после ротации** → проверить ПОРЯДОК:
   ключ обязан попасть в набор РАНЬШЕ, чем им подписан первый токен. Обратный
   порядок даёт громкий и мгновенный отказ у каждого потребителя. Тихое зеркало
   той же ошибки — снятие ключа, пока живы подписанные им токены: отказ приходит
   не сразу, а когда у потребителя истечёт кэш набора, то есть у разных
   потребителей в разное время и уже без связи с действием. Отсрочка снятия для
   того и вычисляется из срока токена и потолка чужого кэша, а не выбирается.

## P3 — Миграции не применились / pod не стартует

Схема — `kacho_iam`, миграции — goose, прогоняются отдельным бинарем
`cmd/migrator` (`bin/kacho-migrator up`). Если схема отстает от кода — pod
падает на старте или RPC отдают неожиданные ошибки.

**Диагностика:**

```bash
# Лог старта — ошибки миграции/схемы.
kubectl -n kacho logs -l app=kacho-iam --tail=200 | grep -iE "migrat|goose|schema|relation .* does not exist"

# Текущая версия goose.
kubectl -n kacho exec deploy/postgres -- \
  psql -c "SELECT version_id, is_applied, tstamp FROM kacho_iam.goose_db_version ORDER BY id DESC LIMIT 5;"
```

**Действия:**

1. **Миграция упала на полпути** → разобрать причину по логам migrator; чинить
   **только новой** миграцией — применную миграцию не редактировать.
2. **Pod опередил миграцию** (rollout раньше migrator-job) → дождаться/перезапустить
   migrator-job, затем pod.
3. Локально вне kind: `KACHO_IAM_DB_PASSWORD=<...> bin/kacho-migrator up`.

## Cluster-admin grants

Cluster-admin-привязки выдаются через internal-only `InternalClusterService`
(`:9091`, mTLS) — на публичном TLS их нет (запрет #6). Хранятся в
`kacho_iam.cluster_admin_grants`: `granted_until IS NULL` — постоянный grant,
непустой `granted_until` — с истечением.

**Инвентаризация:**

```bash
# Текущие активные cluster-admin (denormalized snapshot).
grpcurl -d '{}' <mTLS-flags> kacho-iam:9091 \
  kacho.cloud.iam.v1.InternalClusterService/ListAdmins

# Либо напрямую в БД.
kubectl -n kacho exec deploy/postgres -- psql -c "
SELECT id, subject_id, granted_by, granted_at, granted_until
FROM kacho_iam.cluster_admin_grants
ORDER BY granted_at DESC;
"
```

**Действия:**

1. Выдать cluster-admin → `InternalClusterService/GrantAdmin`
   (`subject_type=USER`, `subject_id=usr_...`). Возвращает `Operation` (async).
2. Отозвать → `InternalClusterService/RevokeAdmin`. Self-revoke и revoke
   последнего админа отвергаются (`FailedPrecondition`) — это защита от
   полной потери cluster-admin.
3. Все вызовы требуют verified client-cert (mTLS) и проходят in-handler
   проверка отношения + acr-floor; «достучаться без сертификата» по `:9091` нельзя.

## P3 — audit_outbox растет без consumer'а

**Симптомы:**
- `kacho_iam.audit_outbox` копит строки со `status='pending'`, не drain'ится.

**Действия:**

1. `kacho-iam` сам не доставляет `audit_outbox` наружу — ожидается external
   consumer (SIEM-shipper), читающий очередь.
2. Если consumer'а нет — это не отказ IAM: очередь можно периодически
   подрезать (`DELETE WHERE status='sent' AND created_at < now() - interval '30d'`),
   pending-строки не трогать до подключения shipper'а.
3. Подключить SIEM-shipper (вне scope kacho-iam).

## Утилитарные команды

```bash
# psql (от корня репозитория).
make -C deploy psql SVC=iam

# Tail logs.
kubectl -n kacho logs -l app=kacho-iam -f --tail=200

# Состояние всех outbox-очередей.
kubectl -n kacho exec deploy/postgres -- psql -c "
SELECT 'fga'              AS q, count(*) FILTER (WHERE sent_at IS NULL) AS pending, max(created_at) AS last FROM kacho_iam.fga_outbox
UNION ALL SELECT 'subject_change', count(*),                                       max(created_at)       FROM kacho_iam.subject_change_outbox
UNION ALL SELECT 'resource_reconcile', count(*),                                   max(created_at)       FROM kacho_iam.resource_reconcile_outbox
UNION ALL SELECT 'audit',          count(*) FILTER (WHERE status='pending'),       max(created_at)       FROM kacho_iam.audit_outbox;
"

# LRO in-flight (метрика на :9095).
kubectl -n kacho exec deploy/kacho-iam -- curl -s http://localhost:9095/metrics | grep kacho_iam_lro_inflight

# Решения authz (rate/итог) — деградация видна по росту deny.
kubectl -n kacho exec deploy/kacho-iam -- curl -s http://localhost:9095/metrics | grep kacho_iam_authz_check_decisions_total

# Принудительно разбудить дренаж сброса кэша края.
kubectl -n kacho exec deploy/postgres -- psql -c "NOTIFY kacho_iam_subject_outbox_added;"

# Graceful restart Deployment.
kubectl rollout restart deploy/kacho-iam -n kacho
kubectl rollout status  deploy/kacho-iam -n kacho --timeout=120s
```

## Запреты в инцидентах

- **НЕ delete'ить `operations` rows вручную** — потеря LRO/audit-следа.
- **НЕ редактировать примененную миграцию** — только новая миграция.
- **НЕ менять `permissions` system-роли** — id пересчитается, все
  AccessBinding'и со ссылкой на роль сломаются.
- **НЕ трогать `relation_fact` руками** — это проекция журнала, а не источник:
  правка переживёт до первой же перезаписи и разойдётся с журналом молча.
- **НЕ публиковать `Internal*`-сервисы на external endpoint** — cluster-admin /
  session-revocations / fgaproxy живут только на `:9091`.

## Связанные компоненты

- [`32-observability.md`](32-observability.md) — где смотреть metrics/logs.
- [`31-deployment.md`](31-deployment.md) — env vars / secrets / listener-порты.
- [`29-relational-verdict.md`](29-relational-verdict.md) — путь «выдал → действует» и бюджет задержки.
- [`../architecture/failure-domains.md`](../architecture/failure-domains.md) — что означает отказ базы.
