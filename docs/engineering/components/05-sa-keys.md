# 05. ServiceAccount Keys (OAuth-credentials: private_key_jwt)

## Назначение

**SA Keys** — удостоверения ServiceAccount: асимметричный ключ (ECDSA P-256), которым
служебная учётка получает access_token по виду выдачи `client_credentials` с
`token_endpoint_auth_method = private_key_jwt` (RFC 7521/7523), федеративный ключ
(утверждение внешнего издателя по перечню доверенных субъектов) и базовый секрет
(`SECRET`, предъявляется как есть).

> [!important] Контур выдачи ОДИН (kaname#362)
>
> Ключевую пару и федеративный ключ обменивает **токен-эндпоинт платформы**
> (`POST /iam/v1/token`), а токен выпускает **наш** подписант. Регистрации клиента
> у внешнего поставщика выдача не заводит, и имени, назначенного им, не хранит:
> столбец зеркала снят миграцией
> `20260928231124_provider_mirror_leaves_the_credential_tables.sql`, поле — из
> контракта (номер 3 зарезервирован). Посадка без объявленного эндпоинта
> (`authn.client-token.enabled`) ключевую пару и федеративный ключ **не выдаёт**:
> `Issue` отвечает `FAILED_PRECONDITION` с именем настройки. Секрет обмена не
> требует и выдаётся и там. Разбор ухода выдачи от прежнего издателя —
> [`architecture/sa-key-issuance-leaves-the-provider.md`](../architecture/sa-key-issuance-leaves-the-provider.md),
> порядок снятия столбца —
> [`architecture/provider-mirror-column-retirement.md`](../architecture/provider-mirror-column-retirement.md).

Каждый ключ-пара **выпущен kaname**:

- **`private_key_pem`** — отдается клиенту ОДИН РАЗ в ответе `IssueSAKey`,
  никогда не хранится в kaname.
- **`public_key`** — kaname держит SPKI-PEM в
  `service_account_oauth_clients.public_key_pem`; именно эта половина сверяет
  подпись `client_assertion` при обмене.

`client_secret` в системе нет. Запрос access_token: клиент сам подписывает
JWT-assertion приватным ключом, кладёт его в `client_assertion` и POST'ит на
токен-эндпоинт платформы. Клиентом он называет себя идентификатором строки ключа
(`iss`/`sub` = `keyId`); второго имени у ключа нет.

**Защита приватного ключа:** `private_key_pem` показывается **один раз** в
ответе `IssueSAKey`. После этого `OpsResponseRedactor`
(`internal/repo/kaname/pg/ops_response_redactor.go`) выполняет single-statement
UPDATE на `operations.response_data`, очищая поле `private_key_pem`
(а также legacy `client_secret`, который всегда пустой).
Повторный `GET /operations/{id}` после redaction даст response без ключа.
Это защищает от replay через operation-id.

**Преимущества над client_secret_basic (legacy):**

- ✅ private_key никогда не покидает client после issuance.
- ✅ Секрета не хранит никто: у платформы только открытая половина.
- ✅ Strong crypto (asymmetric ES256 vs shared secret).
- ✅ Стандартный паттерн асимметричной аутентификации service-аккаунтов.

**Use-cases:**

- Issue первого ключа при provision'е SA.
- Ротация: Issue новый ключ → обновить CI/secrets → Revoke старый.
- Revoke компрометированного ключа.

**Ограничения:**

- Обмен ключевой пары и федеративного ключа идёт только на `POST /iam/v1/token`;
  без объявленного эндпоинта `Issue` этих видов отвечает `FAILED_PRECONDITION`
  с именем `authn.client-token.enabled`.
- `private_key_pem` не восстановим после первого ответа (no "show key again").
- `enabled=false` SA → Issue блокируется (снять состояние — действием
  `ServiceAccountService.Disable`/`Enable`, см. [`04-service-account.md`](04-service-account.md)).
- Алгоритм фиксирован на `ES256` (RS256 / EdDSA — будущее расширение).

## Доменная модель — `service_account_oauth_clients`

| Поле                  | Тип                  | Обязательное | Immutable | Описание                                  |
|-----------------------|----------------------|--------------|-----------|-------------------------------------------|
| `id`                  | TEXT (`soc_...`)     | да           | да        | id записи; им же клиент себя называет.    |
| `sva_id`              | `ServiceAccountID`   | да           | да        | FK → `service_accounts(id)`.              |
| `description`         | TEXT                 | нет          | —         | Free-form, ≤256 chars.                    |
| `created_by_user_id`  | TEXT                 | да           | да        | Ответственный за выпуск (audit). В запросе поле необязательно: край подставляет человеку — вызывающего, служебной учётке — владельца аккаунта целевой учётки. |
| `created_at`          | TIMESTAMPTZ          | да (server)  | да        | UTC.                                      |
| `expires_at`          | TIMESTAMPTZ          | нет          | —         | Срок жизни ключа. **Энфорсится** (см. ниже). NULL = бессрочный. |
| `last_used_at`        | TIMESTAMPTZ          | нет          | —         | Best-effort touch.                        |
| `public_key_pem`      | TEXT (SPKI PEM)      | да           | да        | SPKI ECDSA P-256 public key.              |
| `key_algorithm`       | TEXT                 | да           | да        | `ES256` (`RS256`/`EdDSA` future).         |

**ID prefix:** `soc` (запись в БД, формат `soc_[crockford-17]`).

> **Имя клиента — идентификатор записи (задачи #1120, kaname#362).** В ответе
> выдачи `clientId` равен `keyId`. Столбца с именем клиента у прежнего издателя
> больше нет; ограничения вида и формы (`*_credential_kind_ck`,
> `*_credential_shape_ck`) держат инварианты трёх видов без него.

**DB table:** `kaname.service_account_oauth_clients` (squashed baseline
`internal/migrations/0001_initial.sql`).

**FK contract:** CASCADE delete при удалении SA (в БД); снаружи службы снимать
нечего — регистрации у внешнего поставщика у ключа нет.

### Срок жизни ключа (`expires_at`)

Выставляется на Issue: явный `ttl_seconds` → иначе `KANAME_SAKEY_DEFAULT_TTL`
(90d) → иначе NULL. Потолок — `KANAME_SAKEY_MAX_TTL` (365d), запрос сверх него
отвергается `InvalidArgument` до всякой записи.

Энфорсится на пути обмена ключа на токен одним предикатом
(`expires_at != NULL && expires_at <= now`). Путей было два; докер-полоса выбыла из них вместе
с приёмом ключевого материала в поле пароля — она принимает только базовый токен доступа, и
срок его проверяет авторитет базового удостоверения, а не эта таблица:

| Путь | Точка проверки | Что видит клиент |
|---|---|---|
| Токен-эндпоинт платформы: `client_assertion` → `POST /iam/v1/token` | реестр утверждений (`AssertionClientRepo`) | отказ обмена |
| Docker-token `/iam/token` | — | ключ здесь **не предъявляется**: полоса принимает только базовый токен доступа |

Граница включительная: в момент `expires_at` ключ уже мёртв. Сравнение — по
инстанту (не по настенным полям), поэтому зона хранения роли не играет.

**`NULL` = бессрочный, а не невалидный.** Так лежит bootstrap-admin-маппинг (#58)
и все строки, созданные до появления TTL-ручек. Ограничивать их время — работа
выдающей стороны (конфигурационный ключ `sakey-default-ttl`, поле `AuthN.SAKeyDefaultTTL`),
а не проверяющей.

Уже выданный access-token переживает истечение ключа только до своего срока
(`authn.client-token.token-ttl`, урезанный до остатка жизни клиента). Гейт
закрывает выдачу НОВЫХ токенов; истёкшие строки снимает уборщик
(`jobs.expired-credential-reclaim`).

## Sequence diagram — Issue

```mermaid
sequenceDiagram
    autonumber
    participant Admin
    participant GW as api-gateway
    participant IAM as kaname :9090
    participant DB as Postgres
    participant Redactor as OpsResponseRedactor

    Admin->>GW: POST /iam/v1/serviceAccounts/{saId}/keys
    GW->>IAM: SAKeyService.Issue
    alt токен-эндпоинт платформы не объявлен и вид не SECRET
        IAM-->>GW: FailedPrecondition "credential_kind KEYPAIR: authn.client-token.enabled is false …"
    end
    IAM->>DB: SELECT sa WHERE id=$saId
    alt sa.enabled=false
        IAM-->>GW: FailedPrecondition "ServiceAccount <id> is disabled and cannot be issued a key"
    end
    IAM->>IAM: ecdsa.GenerateKey(P-256) → {priv_pem, pub_pem}; имя клиента := id записи
    IAM->>DB: BEGIN
    IAM->>DB: INSERT service_account_oauth_clients<br/>(soc_id, sva_id, public_key_pem, key_algorithm, declared_audiences, credential_kind)
    IAM->>DB: COMMIT
    IAM->>DB: UPDATE operations<br/>SET done=true, response=IssueSAKeyResponse{client_id=soc_…, private_key_pem, public_key_pem, algorithm:"ES256", key_id:soc_…}
    IAM-->>GW: Operation (done=true, response с private_key_pem)
    GW-->>Admin: 200 {client_id, private_key_pem, public_key_pem, algorithm, key_id}

    Note over Redactor,DB: Sync after MarkDone (idempotent)
    Redactor->>DB: SELECT response_type, response_data FROM operations WHERE id=$opId
    Redactor->>Redactor: Unmarshal Any → IssueSAKeyResponse
    Redactor->>Redactor: private_key_pem := ""<br/>client_secret := "" (legacy field)
    Redactor->>DB: UPDATE operations SET response_data=$new WHERE id=$opId
```

## Sequence diagram — Revoke

```mermaid
sequenceDiagram
    autonumber
    participant Admin
    participant IAM
    participant DB

    Admin->>IAM: SAKeyService.Revoke {sak_id}
    IAM->>DB: DELETE FROM service_account_oauth_clients WHERE id=$sak AND sva_id=$sa<br/>(+ audit-row в той же TX; триггер пишет отсечку отчеканенного)
    IAM-->>Admin: Operation done=true
    Note over Admin,DB: Новых токенов по ключу не выпустить: реестр его не разрешает.<br/>Выданные отсекаются на предъявлении (kaname_sa_key_id).
```

## API surface

### Public gRPC (порт 9090)

| RPC       | Sync/Async | Описание                                              |
|-----------|------------|-------------------------------------------------------|
| `Issue`   | async      | Выпускает OAuth-ключ. Secret в response (один раз).   |
| `Revoke`  | async      | Удаляет строку ключа; отчеканенное отсекается.        |
| `List`    | sync       | Список ключей для SA (без секретов).                  |

### REST mapping

| HTTP    | Path                                                | gRPC mapping           |
|---------|-----------------------------------------------------|------------------------|
| POST    | `/iam/v1/serviceAccounts/{saId}/keys`               | `SAKeyService.Issue`   |
| DELETE  | `/iam/v1/serviceAccounts/{saId}/keys/{keyId}`       | `SAKeyService.Revoke`  |
| GET     | `/iam/v1/serviceAccounts/{saId}/keys`               | `SAKeyService.List`    |

> [!note] Обе таблицы называли методы длинными именами — так зовутся сообщения
> запроса и use-case'ы, но не RPC
> Контракт объявляет три метода короткими именами (выпуск, список, отзыв); длинные
> формы живут в именах сообщений (`IssueSAKeyRequest`) и в именах use-case'ов Go.
> Ошибка была устойчива к проверке свежести: живая перепроверка координаты вида
> «сервис.метод» ищет **имя метода** по всему дереву контрактов, а `IssueSAKey`
> там встречается — в имени сообщения. Отсюда правило: пару «сервис + метод»
> сверять с объявлением **этого** сервиса, а не с наличием слова.

## Конфигурация

Опись настроек службы одна — справочник посадки
`docs/content/install/configuration.mdx`. Ручки поставщика личности, через
которого выпуск регистрирует OAuth-клиент ключа, живут в секции `authn`; как
приходит административный предъявитель — `04-service-account.md`
§Конфигурация.

## Как пользоваться

### Issue

```bash
RESP=$(curl -s -X POST http://localhost:18080/iam/v1/serviceAccounts/$SA_ID/keys \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"description":"CI runner key"}')
OP_ID=$(echo "$RESP" | jq -r .id)
# poll до done=true; путь домен-агностичен — без имени сервиса в начале
RESULT=$(curl -s "http://localhost:18080/operations/$OP_ID" -H "Authorization: Bearer $TOKEN")
CLIENT_ID=$(echo "$RESULT" | jq -r .response.client_id)
KEY_ID=$(echo    "$RESULT" | jq -r .response.key_id)
echo "$RESULT" | jq -r .response.private_key_pem > sa.key  # ← сохранить;
                                                            #   потом <redacted>
echo "$RESULT" | jq -r .response.public_key_pem  > sa.pub
echo "CLIENT_ID=$CLIENT_ID  KEY_ID=$KEY_ID  ALG=ES256"
```

### Получить SA access_token (private_key_jwt, RFC 7521/7523)

Утверждение отправляется на токен-эндпоинт платформы, `aud` утверждения равен
объявленному издателю платформы. Полная форма запроса и требования к членам
утверждения — на странице токен-эндпоинта в опубликованной документации сервиса.

```bash
# 1. Подписываем JWT-assertion sa.key'ом. Пример на python-jose:
python3 <<'PY' > assertion.txt
import time, json, uuid
from jose import jwt
priv = open('sa.key').read()
claims = {
  "iss": "$CLIENT_ID", "sub": "$CLIENT_ID",
  "aud": "$PLATFORM_ISSUER",
  "exp": int(time.time()) + 60, "jti": uuid.uuid4().hex,
}
print(jwt.encode(claims, priv, algorithm="ES256",
                 headers={"kid": "$KEY_ID"}))
PY

# 2. POST на токен-эндпоинт платформы с client_assertion (нет basic-auth, нет client_secret).
curl -X POST "http://localhost:18080/iam/v1/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CLIENT_ID" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$(cat assertion.txt)" \
  -d "audience=$AUDIENCE"
```

### Revoke

```bash
curl -X DELETE http://localhost:18080/iam/v1/serviceAccounts/$SA_ID/keys/$KEY_ID \
  -H "Authorization: Bearer $TOKEN"
```

### List

```bash
curl http://localhost:18080/iam/v1/serviceAccounts/$SA_ID/keys -H "Authorization: Bearer $TOKEN" | jq
# → [{id, svaId, createdAt, expiresAt, lastUsedAt, name, labels, credentialKind}]
```

### Идемпотентность

`IssueSAKey` НЕ идемпотентен — каждый вызов создаёт новую строку ключа.

`RevokeSAKey` идемпотентен **успехом**: повторный отзыв, отзыв идентификатора,
которого не было никогда, и отзыв ключа ЧУЖОЙ учётки дают один и тот же исход —
операция завершается успешно, ответ несёт `keyId` и `revokedAt`, снято при этом
ничего не было. Ключ чужой учётки вызов переживает: владение стоит внутри самого
оператора снятия, а не в проверке перед ним.

> Прежде исход был не один. Это противоречило приёмке базового токена
> (`BAT-1-44`, где исход повторного отзыва назван поимённо — успех) и вместе с
> тем расходилось с требованием скрытия существования (`security.md`
> §Hardening #6): пока исходов больше одного, по различию между ними узнают то,
> что скрытие обязано держать неразличимым. Исход теперь один, потому что ветки,
> на которой они могли бы разойтись, в коде больше нет — владение стоит внутри
> самого оператора снятия. Изменение и его потребители — задача #1216.

### Типичные ошибки

| Сценарий                             | gRPC code             | HTTP | Текст                                          |
|--------------------------------------|------------------------|------|------------------------------------------------|
| SA disabled                          | `FAILED_PRECONDITION`  | 400  | `ServiceAccount <id> is disabled and cannot be issued a key` |
| Токен-эндпоинт платформы не объявлен (KEYPAIR / FEDERATED) | `FAILED_PRECONDITION` | 400 | `credential_kind <вид>: authn.client-token.enabled is false — …` |
| Номер вида вне словаря (в том числе снятый 4) | `INVALID_ARGUMENT` | 400 | `credential_kind: unknown credential kind <номер>` |
| SA не найден                         | `NOT_FOUND`            | 404  | `ServiceAccount sva_xxx not found`             |
| Anonymous IssueSAKey                 | `UNAUTHENTICATED`      | 401  | `anonymous principal rejected`                 |
| Anonymous Get operation с redacted   | `NOT_FOUND`            | 404  | (anti-replay guard — operation/anon)           |

## Как воспроизвести локально

Команды запускаются **от корня репозитория**.

```bash
make -C deploy dev-up
kubectl -n kacho port-forward svc/api-gateway 18080:8080 &

# Newman: отдельного набора «ключи SA» нет — они покрыты набором служебной
# учётки и набором токена по ключу.
./services/iam/tests/newman/scripts/run.sh --service iam-service-account
./services/iam/tests/newman/scripts/run.sh --service authz-sa-apitoken

# Integration (testcontainers):
go test -short -count=1 -timeout 120s \
  -run "TestSAKey|TestOpsResponseRedactor|TestIssueSAKey" \
  ./services/iam/internal/clients/ ./services/iam/internal/apps/kaname/api/sa_keys/
```

> [!note] Прежняя команда звала набор, которого нет, и передавала имя набора
> переменной окружения, которую прогонщик обнуляет первым делом
> Набора с таким именем среди сгенерированных коллекций сервиса не существует, а
> имя, переданное окружением, затиралось — то есть команда завершалась успехом,
> прогнав **весь** сервис вместо запрошенного набора. Успех без предмета читается
> как исполненная проверка, поэтому обе половины исправлены разом.

## Подробности реализации

- **Handler и use-case живут в одном пакете** `internal/apps/kaname/api/sa_keys/`: точки входа
  `Handler.Issue` / `Handler.List` / `Handler.Revoke` в `handler.go`, выпуск ключа — `keys.go`,
  журналирование — `audit.go`. Отдельного файла со сводкой use-case'ов у пакета нет.
- **Repo:** SA-OAuth-clients-репо в `internal/repo/kaname/pg/` (через `NewSAOAuthClientRepo`).
- **Redactor:** `internal/repo/kaname/pg/ops_response_redactor.go`. SELECT
  `(response_type, response_data)` из `operations`, unmarshal `Any` →
  `IssueSAKeyResponse`, reflect-clear поле `private_key_pem` (+ legacy
  `client_secret`), UPDATE обратно. Idempotent (повторный clear no-op).
  Реализация без `jsonb_set` — operations хранит proto-bytes, не JSON.
- **AntiAnonymous integration:** `operationspb.Handler.Get` (общий слой) has anti-leak gate:
  если operation содержит secret-поле и principal anonymous — возвращает
  NotFound (даже если operation существует). См.
  `pkg/operations/operationspb/handler_test.go` (полоса сведена в общий слой).

## Gotchas / известные ограничения

- **Private-key видимость окно** — между MarkDone и UPDATE redaction есть
  окно миллисекунд, когда первый GET вернет `private_key_pem`. Это
  by-design — это и есть единственная допустимая видимость ключа.
- **Replay через operation-id** — даже после redaction оператор знает
  `operation_id`, но `response.private_key_pem` уже `<redacted>`. Legacy
  `response.client_secret` всегда пуст и тоже редактируется
  для wire-compat.
- **Алгоритм фиксирован `ES256`** — domain.Validate допускает RS256/EdDSA
  для будущих расширений, но текущая ECDSA P-256-only генерация
  (`internal/apps/kaname/api/sa_keys/keys.go`) выставляет только `ES256`.
- **Строк прежнего потока нет.** Миграция снятия столбца зеркала отказывала,
  пока лежала хоть одна строка вида LEGACY либо строка с именем клиента у
  прежнего издателя (строка чеканки бутстрапа — названное исключение).

## Связанные компоненты

- [`04-service-account.md`](04-service-account.md) — родительский ресурс.
- [`10-operations.md`](10-operations.md) — operations + redactor.

## Ссылки на код

- `internal/apps/kaname/api/sa_keys/usecases.go` — `IssueSAKeyUseCase` /
  `RevokeSAKeyUseCase` / `ListSAKeysUseCase`.
- `internal/apps/kaname/api/sa_keys/keys.go` — `generateES256Key` (ECDSA P-256
  keypair → PKCS#8 / SPKI PEM).
- `internal/apps/kaname/api/sa_keys/handler.go`.
- `internal/repo/kaname/pg/ops_response_redactor.go` (тот же файл, что назван выше — прежде
  здесь стоял другой каталог, и две ссылки об одном предмете расходились).
- `internal/migrations/0001_initial.sql` — таблица
  `service_account_oauth_clients` (`public_key_pem`, `key_algorithm`);
  `internal/migrations/20260928231124_provider_mirror_leaves_the_credential_tables.sql`
  — снятие столбца зеркала и вида LEGACY.
- `pkg/operations/operationspb/handler_test.go` (полоса сведена в общий слой).
- `internal/service/token_enrichment_service.go` — SA-claims path
  (`kaname_principal_type=service_account`, `kaname_principal_id`,
  `kaname_account_id`).
- `cmd/kaname/token_claims.go` — `tokenEnrichSAAdapter` wiring: чтение
  служебной учётки по строке реестра. Поиск ключа по имени клиента у прежнего
  поставщика ушёл вместе с его хуками (kaname#363).
