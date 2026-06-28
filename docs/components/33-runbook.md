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
- Рост `fga_outbox` backlog ИЛИ OpenFGA недоступна.

**Быстрая диагностика:**

```bash
# Pod alive?
kubectl -n kacho get pod -l app=kacho-iam

# OpenFGA reachable? (default endpoint — KACHO_IAM_OPENFGA_ENDPOINT)
kubectl -n kacho exec deploy/kacho-iam -- curl -sf http://kacho-umbrella-openfga:8080/healthz

# DB reachable?
cd kacho-deploy && make psql SVC=iam   # либо nc -zv <db-host> 5432

# fga_outbox растет (pending = sent_at IS NULL)?
kubectl -n kacho exec deploy/postgres -- \
  psql -c "SELECT count(*) FROM kacho_iam.fga_outbox WHERE sent_at IS NULL;"

# Логи последние 5min.
kubectl -n kacho logs -l app=kacho-iam --since=5m | grep -E "ERROR|FATAL|fga|openfga"
```

**Действия:**

1. **OpenFGA down** → `kubectl rollout restart deploy/kacho-umbrella-openfga`.
   `kacho-iam` сам переподключится (HTTP-клиент с retry).
2. **DB down** → escalate DBA. `kacho-iam` падает fail-closed (мутации
   возвращают `UNAVAILABLE`).
3. **kacho-iam OOM/crash** → `kubectl rollout restart deploy/kacho-iam`;
   проверить memory limits.
4. **fga_outbox backlog огромный** (>10k pending) — см. раздел про drainer ниже:
   drainer все подтянет, но grant→Check propagation временно нарушена.

**Escalation:** SRE on-call → IAM team.

## P2 — fga_outbox drainer отстает

AccessBinding-гранты транслируются в OpenFGA-tuples через `fga_outbox`-drainer
внутри той же writer-tx. Drainer — NOTIFY-driven (канал `kacho_iam_fga_outbox`)
с poll-catch-up. Отставание означает, что свежий grant уже в IAM-DB, но в FGA
tuple еще не записан → `Check` отдает stale-decision.

**Симптомы:**
- Пользователь получил grant, но `Check` отдает `deny` (доступ «не появился»).
- Растет число pending-строк в `fga_outbox`.

**Диагностика:**

```bash
# Сколько pending и насколько стара самая старая.
kubectl -n kacho exec deploy/postgres -- psql -c "
SELECT count(*)                        AS pending,
       now() - min(created_at)         AS oldest_pending_age,
       max(last_error)                 AS last_error
FROM kacho_iam.fga_outbox
WHERE sent_at IS NULL;
"

# Ошибки apply в логах.
kubectl -n kacho logs -l app=kacho-iam --since=10m | grep -E "fga_outbox|fga.apply"
```

**Действия:**

1. **OpenFGA down/slow** → причина чаще всего тут (apply пишет в FGA).
   Восстановить OpenFGA (см. P1) — drainer догонит автоматически.
2. **`last_error` повторяется** (например невалидный tuple-type) → проверить
   FGA-модель против регистрируемых типов; строка с непустым `last_error`
   ретраится по `attempt_count`.
3. **Drainer завис** (NOTIFY пропущен) → принудительно разбудить:
   ```bash
   kubectl -n kacho exec deploy/postgres -- psql -c "NOTIFY kacho_iam_fga_outbox;"
   ```
   Если не помогает — `kubectl rollout restart deploy/kacho-iam` (drainer
   переустановит `LISTEN` и сделает poll-catch-up на старте).

Детали grant→tuple-цепочки — [`28-fgahook.md`](28-fgahook.md); latency-бюджет
Check — [`29-openfga-check.md`](29-openfga-check.md).

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

## P2 — JWKS rotation сломала подпись токенов

OIDC JWKS-ключи подписи живут в `kacho_iam.oidc_jwks_keys`; ротацию выполняет
отдельный бинарь `jwks-rotator` (`once` — один цикл из CronJob; `daemon` —
tick ~1h со случайным сдвигом). Активный ключ — строка с `current = true`. Issuer токенов —
Ory Hydra; api-gateway валидирует JWT по опубликованному JWKS.

**Симптомы:**
- api-gateway отдает 401 на все JWT после цикла ротации.
- В логах валидации — `unknown kid` / signature mismatch.

**Диагностика:**

```bash
# Текущий активный ключ присутствует?
kubectl -n kacho exec deploy/postgres -- psql -c "
SELECT kid, alg, current, rotated_at, expires_at
FROM kacho_iam.oidc_jwks_keys
ORDER BY created_at DESC LIMIT 5;
"

# CronJob/daemon отработал?
kubectl -n kacho logs job/kacho-iam-jwks-rotator --tail=100 2>/dev/null \
  || kubectl -n kacho logs -l app=kacho-iam-jwks-rotator --tail=100
```

**Действия:**

1. **Нет строки `current = true`** → ротация прервалась между «вставить новый»
   и «промотировать». Перезапустить один цикл: `jwks-rotator once`
   (внутри `Rotate` — advisory xact-lock per-alg, параллельные pod'ы безопасны).
2. **Ключ есть, но gateway его не видит** → api-gateway кеширует JWKS;
   рестартнуть gateway-pod, чтобы сбросить кеш.
3. **Hydra issuer недоступен** → токены не минтятся вовсе; восстановить Hydra,
   далее повторить логин.

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
   ReBAC-Check + acr-floor; «достучаться без сертификата» по `:9091` нельзя.

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
# psql.
cd kacho-deploy && make psql SVC=iam

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

# Принудительно разбудить fga_outbox drainer.
kubectl -n kacho exec deploy/postgres -- psql -c "NOTIFY kacho_iam_fga_outbox;"

# Graceful restart Deployment.
kubectl rollout restart deploy/kacho-iam -n kacho
kubectl rollout status  deploy/kacho-iam -n kacho --timeout=120s
```

## Запреты в инцидентах

- **НЕ delete'ить `operations` rows вручную** — потеря LRO/audit-следа.
- **НЕ редактировать примененную миграцию** — только новая миграция.
- **НЕ менять `permissions` system-роли** — id пересчитается, все
  AccessBinding'и со ссылкой на роль сломаются.
- **НЕ disable'ить OpenFGA «для починки»** — это полный outage authz.
- **НЕ публиковать `Internal*`-сервисы на external endpoint** — cluster-admin /
  session-revocations / fgaproxy живут только на `:9091`.

## Связанные компоненты

- [`32-observability.md`](32-observability.md) — где смотреть metrics/logs.
- [`31-deployment.md`](31-deployment.md) — env vars / secrets / listener-порты.
- [`28-fgahook.md`](28-fgahook.md) — grant → FGA-tuple цепочка (fga_outbox).
- [`29-openfga-check.md`](29-openfga-check.md) — Check latency budget (sub-second).
