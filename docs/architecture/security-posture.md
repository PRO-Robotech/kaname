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

## Trust-gating форвардинга principal (оба слушателя)

`x-kacho-principal-*` metadata несет identity вызывающего пользователя, проброшенную
форвардером (api-gateway после JWT-валидации; consumer-модули на своем request-path).
На **обоих** gRPC-слушателях эта metadata раскрывается downstream (в
`operations.principal_*` / audit / scope-filter) **только** когда peer прошел mTLS
client-cert верификацию (`CertIdentityExtract` → `TrustedPrincipalExtract`): на
непроверенном/бессертификатном peer'е форвардинг **снимается** (fallback на
`SystemPrincipal`, трактуется как анонимный). Без этого любой, кто дозвонится до
слушателя, мог бы **подделать** произвольный `user:<victim>` principal (impersonation).

**Почему на `:9090` НЕТ gateway-only pin форвардера.** Публичный слушатель —
**мульти-форвардерный**: помимо api-gateway (tenant-facing user-запросы), каждый
verified consumer-модуль (`kacho-vpc`/`compute`/`nlb`/`geo`) дозванивается до
`ProjectService.Get` и форвардит end-user principal ради tenant scope-filter. Пин
«только gateway» сломал бы эту кросс-сервисную валидацию проектов. Достаточная защита —
internal-CA + `RequireAndVerifyClientCert` на `:9090` (слушатель доступен только
verified kacho-модулям) + trust-gate выше (unverified peer не может подделать
principal). Остаточный риск (скомпрометированный verified-модуль подделывает
произвольного user'а) присущ модели «доверенного форвардера» и митигируется
scope'ом internal-CA + NetworkPolicy + hardening'ом pod'ов модулей.

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

### Остаточный риск: PDP как enumeration-oracle (by-design trade-off)

PDP по своей природе — **оракул решений авторизации**: он отвечает на запросы вида
«разрешено ли `(subject, relation, object)`?» для **произвольного** subject, а не только
для самого вызывающего. Из-за этого аутентифицированный вызывающий, имеющий доступ к
PDP, может **перечислять** authz-отношения о чужих subject'ах (enumeration). Это
**осознанный компромисс**, а не незакрытый баг:

- **Почему нельзя потребовать self-scoped subject** (caller спрашивает только о СЕБЕ):
  api-gateway — единственная authz-front-door платформы — вызывает `Check` с subject'ом
  **end-user'а** (`subj.FGA`), а НЕ со своей транспортной identity; он спрашивает «может
  ли пользователь X сделать Y», не будучи пользователем X. Аналогично consumer-модули
  (`vpc`/`compute`) на bootstrap вызывают `ListObjects`/`ListSubjects` про subject,
  который не совпадает с их транспортной identity. Требование «subject == caller»
  **сломало бы** и per-user Check у gateway, и кросс-сервисный preflight. Поэтому
  self-scoping не применяется.
- **Чем ограничен риск.** (1) Транспорт: production-strict + mTLS/JWT — PDP недостижим
  анонимно из-вне периметра (анонимный запрос fail-closed до backend'а); слушатель
  доступен только verified-модулям и JWT-аутентифицированным user'ам через edge.
  (2) Данные: PDP возвращает лишь tenant-facing «разрешено/запрещено» по запрошенному
  триплету — никаких инфра-чувствительных данных (placement/underlay), см. `security.md`.
  (3) Сеть: NetworkPolicy сегментирует доступ к `:9090`.

Вывод: публичность PDP — требование его роли; безопасность строится на транспортной
аутентификации + строгом режиме + отсутствии data-leak, а не на сокрытии endpoint'а или
на (ломающем flow) self-scoping.

#### Оценено (r5-аудит): dev-mode inner-gate и read-surface backstop

Два defense-in-depth-замечания 5-го аудита, оба **не** меняющие prod-постуру:

- **`AuthorizeService.authorizeAnonymousPeer` fail-open в `mode=dev`.** Внутренний
  gate PDP отдаёт allow анонимному/system-принципалу только когда `prodMode==false`
  (`internal/apps/kacho/api/authorize/caller_authority.go`). Это **тот же** dev-mode
  компромисс, что и общий anonymous-allow: в dev нет mTLS, поэтому public- и
  internal-слушатели неразличимы, и легитимный внутримодульный PDP-вызов в dev тоже
  анонимен — потребовать deny означало бы сломать dev-режим (и inter-module
  preflight), а не закрыть реальную дыру. **По умолчанию** `authn.mode=production`
  (defaults.go) — gate строго fail-closed; сценарий требует развернуть стенд в
  `mode=dev`, что уже запрещено (`security.md`: dev — только локальные фикстуры).
  Сознательно **не** меняем на deny-in-dev (сломало бы flow, prod уже закрыт).
- **Anti-anonymous interceptor не даёт read-path backstop.** `AntiAnonymousUnary`
  пропускает read-суффиксы (Get/List/…/Check) для анонимного вызывающего, делегируя
  authz каждому read use-case (сегодня все они fail-closed: `AllowsVGet`, listauthz
  с anonymous→empty, FGA-error→fail-closed). Замечание — про архитектурную хрупкость
  (новый read-RPC, забывший in-use-case gate, не будет пойман на уровне интерсептора),
  а не про текущую дыру. Предложенный fix (явный per-RPC allowlist вместо суффиксного
  bypass) — широкая переделка security-интерсептора с риском регрессии на всей
  read-поверхности; требует отдельного acceptance + full read-suite прогона и **не**
  сворачивается в hardening-pass. CI-gate `make audit-list-filter` уже держит
  List-фильтрацию под контролем. Отслеживается отдельной задачей.

## Целостность данных authz

Гранты `AccessBinding` транслируются в OpenFGA-tuples через transactional-outbox
(`fga_outbox`) внутри той же writer-транзакции — запись гранта и постановка tuple в
очередь атомарны; drainer доставляет at-least-once и идемпотентно. Это исключает
рассинхрон «грант есть в БД, а tuple в FGA нет».
