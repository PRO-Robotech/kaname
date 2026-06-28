# Security posture — listeners, AuthN/AuthZ, PDP exposure

Документ фиксирует модель безопасности kacho-iam: какие слушатели существуют, как
аутентифицируется и авторизуется каждый запрос, и почему публичный PDP
(`AuthorizeService`) защищается транспортом и строгим режимом, а не «непубличностью».

## Слушатели

| Порт   | Назначение                                  | Транспорт (prod)            |
|--------|---------------------------------------------|-----------------------------|
| `:9090`| Публичный gRPC (tenant-facing API)          | TLS + validated JWT         |
| `:9091`| Cluster-internal gRPC (service→service)     | **mTLS** (verified client-cert) |
| `:9092`| AuthN-webhooks Ory (Kratos provision, Hydra token/refresh) + `/healthz`,`/readyz` | cluster-internal HTTP |
| `:9095`| Prometheus `/metrics`                        | cluster-internal            |

`Internal*`-сервисы (`InternalIAMService`, `InternalUserService`,
`InternalClusterService`, …) живут **только** на `:9091` и никогда не публикуются на
внешнем TLS-endpoint.

## Инвариант: AuthN + AuthZ на каждом запросе обоих слушателей

Правила для публичного и internal слушателей **одинаковы**: ни одного
неаутентифицированного/неавторизованного запроса. Транспорт — mTLS (service→service)
либо TLS+JWT (user→edge); поверх — per-RPC authz-Check через OpenFGA ReBAC. Внутренний
периметр не считается доверенным (defense-in-depth против lateral movement): mTLS на
`:9091` обязателен и не освобождает от authz.

## Публичный PDP (`AuthorizeService`) и режим production-strict

`AuthorizeService` (`Check` / `ListObjects` / `ListSubjects`) — это PDP: api-gateway и
другие потребители вызывают его, чтобы получить решение авторизации. По своей роли он
**обязан** быть доступен на публичном слушателе — следовательно, его защита строится на
транспортной аутентификации и строгом режиме, а не на сокрытии endpoint'а:

- **production-strict** (профиль `deploy/values.prod.yaml`): анонимный вызов
  fail-closed; запрос без валидного principal отклоняется до обращения к backend.
- **mTLS/JWT** на транспорте: вызов PDP несет проверенную identity.
- Решения PDP не раскрывают инфра-чувствительных данных — только tenant-facing
  «разрешено/запрещено» по запрошенному `(subject, relation, object)`.

Режим `dev` (анонимный доступ для локального стенда) допустим **только** в локальной
разработке и CI-фикстурах — никогда в развернутом окружении. Любой кластерный деплой
поднимается с production-strict + mTLS.

## Целостность данных authz

Гранты `AccessBinding` транслируются в OpenFGA-tuples через transactional-outbox
(`fga_outbox`) внутри той же writer-транзакции — запись гранта и постановка tuple в
очередь атомарны; drainer доставляет at-least-once и идемпотентно. Это исключает
рассинхрон «грант есть в БД, а tuple в FGA нет».
