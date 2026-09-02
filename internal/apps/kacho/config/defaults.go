// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"time"

	"github.com/spf13/viper"

	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
)

// RegisterDefaults sets default values for every config key (defaults are
// kept in one place rather than in struct-tags).
//
// DB / port / SSL values match kacho-vpc so both services deploy uniformly
// through kacho-deploy. ENV-prefix is `KACHO_IAM` (vs `KACHO_VPC`), default
// DB-name is `kacho_iam`.
func RegisterDefaults(v *viper.Viper) {
	// logger
	v.SetDefault("logger.level", "INFO")

	// api-server
	v.SetDefault("api-server.endpoint", "tcp://0.0.0.0:9090")
	v.SetDefault("api-server.internal-endpoint", "tcp://0.0.0.0:9091")
	v.SetDefault("api-server.graceful-shutdown", 10*time.Second)
	// Prometheus /metrics HTTP listener — separate cluster-internal port (never
	// the public tenant gRPC surface). Override via KACHO_IAM_API_SERVER__METRICS_ENDPOINT.
	v.SetDefault("api-server.metrics-endpoint", "tcp://0.0.0.0:9095")
	// Docker Registry v2 `/iam/token` auth-server HTTP listener — a SEPARATE,
	// external-reachable plaintext port (ingress-terminated TLS), distinct from
	// the hooks (:9092) and metrics (:9095) listeners. Issuer/service/TTL shape
	// the minted identity-JWT and must match the data-plane's advertised Bearer
	// realm. Override via KACHO_IAM_API_SERVER__REGISTRY_TOKEN__{ENDPOINT,ISSUER,SERVICE,TTL}.
	v.SetDefault("api-server.registry-token.endpoint", "tcp://0.0.0.0:9096")
	v.SetDefault("api-server.registry-token.issuer", "https://api.kacho.local/iam/token")
	// `api-server.registry-token.service` УМОЛЧАНИЯ НЕ ИМЕЕТ намеренно — имя
	// службы реестра объявляет посадка ОДИН раз на обе стороны полосы
	// (`global.kacho.registry.serviceAud`), см. registry_token.go. Незаданное
	// при поднятом слушателе отвергается стражем старта.
	v.SetDefault("api-server.registry-token.ttl", 5*time.Minute)
	// ОКНО ПЕРЕХОДА #1143 — ПУСТО, ТО ЕСТЬ ЗАКРЫТО. Умолчание объявляется здесь
	// ЯВНО, хотя пустая строка и есть нулевое значение поля: viper связывает с
	// переменной окружения только те ключи, о которых знает, и ключ без
	// объявленного умолчания даёт документированную ручку БЕЗ ЧИТАТЕЛЯ —
	// оператор её задаёт, а исход загрузки не меняется. Держит это
	// TestDocumentedEnvName_KeyMaterialWindowUntil.
	// ENV: KACHO_IAM_API_SERVER__REGISTRY_TOKEN__KEY_MATERIAL_WINDOW_UNTIL
	v.SetDefault("api-server.registry-token.key-material-window-until", "")
	// Cluster-INTERNAL Hydra-JWKS proxy HTTP listener (`GET /.well-known/jwks.json`)
	// — a SEPARATE cluster-internal port (default `tcp://0.0.0.0:9097`), served ONLY
	// on the kacho-iam-internal Service (never external, ban #6) over one-way
	// server-TLS. Short-TTL caching reverse-proxy of Hydra's PUBLIC JWKS so the
	// data-plane fetches verification keys from iam (Hydra stays the signer).
	// Override via KACHO_IAM_API_SERVER__JWKS_PROXY__ENDPOINT.
	v.SetDefault("api-server.jwks-proxy.endpoint", "tcp://0.0.0.0:9097")

	// retention — фоновая уборка таблиц, чей рост задаёт внешний (задача #1292).
	//
	// Порогов здесь НЕТ: они вычисляются из `pkg/tokenpolicy` реестром уборки —
	// настраиваемый порог развели бы с предикатом читателя молча.
	//
	// Интервал: верхняя граница числа строк = темп × (срок строки + интервал);
	// при сроке до часа пять минут добавляют к ней около 8 %, то есть величина
	// не определяющая и выбрана по стоимости прогона.
	// ENV: KACHO_IAM_RETENTION__INTERVAL
	v.SetDefault("retention.interval", 5*time.Minute)
	// Партия — длина одного оператора DELETE. Величина того же рода уже живёт в
	// дереве у уборщика края (`gateway/internal/idempotencypg`), менять её без
	// замера незачем.
	// ENV: KACHO_IAM_RETENTION__BATCH
	v.SetDefault("retention.batch", 1000)
	// Потолок партий за проход. Одна партия за тик даёт скорость догона
	// «партия / интервал», и при более высоком темпе записи уборщик не догонит
	// НИКОГДА, оставаясь зелёным по всякой проверке «вызвался ли». Двадцать
	// партий по тысяче за пять минут — 240 тыс. строк в час на предмет, при
	// длительности прохода, ограниченной сверху.
	// ENV: KACHO_IAM_RETENTION__MAX_BATCHES_PER_PASS
	v.SetDefault("retention.max-batches-per-pass", 20)

	// repository
	v.SetDefault("repository.postgres.url", "postgres://iam@localhost:5432/kacho_iam")
	v.SetDefault("repository.postgres.slave-url", "")
	v.SetDefault("repository.postgres.max-conns", 0)
	// Одна реплика — минимальная посадка, которая вообще работает. Ноль здесь
	// означал бы «не проверять»: произведение обратилось бы в ноль и прошло бы
	// любую проверку.
	v.SetDefault("repository.postgres.replica-budget", 1)
	v.SetDefault("repository.postgres.ssl-mode", "disable")
	v.SetDefault("repository.postgres.password-from-env", "KACHO_IAM_DB_PASSWORD")

	// authz — кто принимает решение о доступе.
	//
	// ЗДЕСЬ БЫЛО ДВЕ РУЧКИ — обе про выбор между движком и своей формой, и обе
	// пережили свой предмет: движка больше нет, вердикт считается только в своей
	// базе, выбирать не из чего. Ручка, у которой ноль читателей, — объявленное
	// без предмета: следующий читатель принимает её за переключатель и строит на
	// ней вывод, а она не меняет ничего.
	//
	// Отдельная цена была у второй: срок ожидания сверки составлял 50 мс при
	// бюджете чтения 30 мс, то есть механизм, решений не принимавший, был вправе
	// задержать ответ дольше всего бюджета операции (#751). Он снят вместе с тем,
	// что сверял, — а не «настроен покороче».

	// authn
	// Safe-by-default (prod-readiness F14): an un-configured binary fails CLOSED
	// (production = anonymous → PermissionDenied), never dev (anonymous → full
	// access). Local fixtures / the newman stand opt INTO dev explicitly via
	// KACHO_IAM_AUTH_MODE=dev (values.dev.yaml carries mode: dev).
	v.SetDefault("authn.mode", "production")
	// authn.identity-provider — УМОЛЧАНИЯ НЕТ НАМЕРЕННО (задача #1125).
	//
	// Обе альтернативы разобраны и обе отвергнуты: умолчание `external`
	// заставило бы каждый профиль, поля не объявивший, требовать адресов, у
	// которых нет носителя; умолчание `own` МОЛЧА сняло бы провайдерские
	// требования у профиля, который просто забыли обновить. Умолчание живёт в
	// ПРОФИЛЕ — базовый профиль зонтичного чарта объявляет значение явно.
	//
	// Строки `SetDefault` для этого ключа быть не должно: она и есть то самое
	// умолчание в коде. Свойство держит проба
	// TestF4d01_UnsetIdentityProviderRefusesTheStart — при умолчании она
	// перестала бы наблюдать незаданное значение вовсе.
	// AuthN core — configurable domain + Hydra issuer + hooks. Secrets are
	// resolved from env so they don't sit in YAML/ConfigMap.
	v.SetDefault("authn.domain", "api.kacho.cloud")
	v.SetDefault("authn.hydra-issuer", "")       // resolved via ResolveHydraIssuer() when empty
	v.SetDefault("authn.hydra-jwks-url", "")     // resolved via ResolveHydraJWKSURL() (env KACHO_IAM_HYDRA_JWKS_URL)
	v.SetDefault("authn.hook-shared-secret", "") // no default — security-sensitive
	v.SetDefault("authn.hook-shared-secret-env", "KACHO_IAM_HOOK_TOKEN")
	// Административный предъявитель внешнего поставщика: в YAML пишется ИМЯ
	// переменной, значение — никогда (секрет). Прежде эта ручка читалась прямо
	// из окружения в корне сборки и потому была невидима проверке настройки при
	// старте (задача #1125).
	v.SetDefault("authn.hydra-admin-token-env", "KACHO_IAM_HYDRA_ADMIN_TOKEN")
	v.SetDefault("authn.jwks-encryption-key-hex", "")
	v.SetDefault("authn.jwks-encryption-key-hex-env", "KACHO_IAM_JWKS_ENC_KEY")
	v.SetDefault("authn.hooks-http-endpoint", "tcp://0.0.0.0:9092")
	// Своя чеканка токенов (задача #897). Умолчания заданы ТОЛЬКО у величин,
	// у которых умолчание осмысленно: путь нашей записи набора и срок ключа.
	// У издателя и алгоритма умолчаний НЕТ — подпись умолчанием была бы
	// решением, принятым за оператора.
	v.SetDefault("authn.token-signing.enabled", false)
	v.SetDefault("authn.token-signing.issuer", "")
	v.SetDefault("authn.token-signing.algorithm", "")
	v.SetDefault("authn.token-signing.allowed-algorithms", "")
	v.SetDefault("authn.token-signing.key-set-path", "/.well-known/kacho/jwks.json")
	v.SetDefault("authn.token-signing.key-lifetime", "2160h")
	// Токен-эндпоинт платформы (задача #898). Умолчания заданы ТОЛЬКО у
	// величин, которые описывают НАШ расход и ничего не разрешают: потолок
	// тела и обычный срок токена. У перечня адресатов, адресата по умолчанию и
	// слушателя умолчаний НЕТ — каждое из них расширяет принимаемое либо
	// выставляет поверхность, и умолчание здесь было бы решением, принятым за
	// оператора. Страж старта требует их все, как только эндпоинт включён.
	v.SetDefault("authn.client-token.enabled", false)
	v.SetDefault("authn.client-token.allowed-audiences", "")
	v.SetDefault("authn.client-token.default-audience", "")
	v.SetDefault("authn.client-token.token-ttl", "15m")
	v.SetDefault("authn.client-token.body-ceiling", 64<<10)
	// SA-key одноразовый private_key_pem отдаётся только в op.response; клиент
	// поллит Operation.Get, чтобы его забрать. Затирание выдерживает это окно,
	// иначе клиент проигрывает гонку и получает ПУСТОЕ поле (затирание очищает
	// поле, а не подставляет метку — метки нет). Override —
	// KACHO_IAM_SAKEY_REDACT_GRACE (или KACHO_IAM_AUTHN__SAKEY_REDACT_GRACE).
	v.SetDefault("authn.sakey-redact-grace", 120*time.Second)
	// User-токен: одноразовый private_key_pem отдаётся только в op.response; клиент
	// поллит Operation.Get, чтобы его забрать. Grace-окно выдерживает это окно.
	// Override — KACHO_IAM_USERTOKEN_REDACT_GRACE.
	v.SetDefault("authn.usertoken-redact-grace", 120*time.Second)
	// SA-key lifetime discipline. A service-account key IS the machine's
	// credential, and machine principals are exempt from step-up (a machine has
	// no second factor) — "exempt" is only defensible while the credential is
	// bounded in time. So the omitted-ttl_seconds case resolves to a finite
	// default instead of "never expires", and requests carry an inclusive
	// ceiling. Overrides: KACHO_IAM_SAKEY_DEFAULT_TTL / KACHO_IAM_SAKEY_MAX_TTL.
	v.SetDefault("authn.sakey-default-ttl", 90*24*time.Hour)

	// ── Фоновые задания ────────────────────────────────────────────────────
	//
	// Снятие истёкших удостоверений (задача #1264). Умолчания названы вместе с
	// основанием, а не выбраны: интервал — из точности относительно отсрочки
	// (час даёт около четырёх процентов от суток); отсрочка — продуктовое
	// решение о НАБЛЮДАЕМОСТИ (человек, у которого доступ перестал работать
	// ночью, приходит утром и обязан увидеть ПРИЧИНУ — истёкшую строку в
	// перечне, — а не пустоту); партия ограничивает длительность транзакции.
	//
	// Включено ПО УМОЛЧАНИЮ: гигиена истёкших была обязанностью арендатора
	// ровно потому, что платформа её не делала, и выключенное по умолчанию
	// умолчание оставило бы её там же.
	v.SetDefault("jobs.expired-credential-reclaim.enabled", true)
	v.SetDefault("jobs.expired-credential-reclaim.interval", time.Hour)
	v.SetDefault("jobs.expired-credential-reclaim.grace", tokenpolicy.ExpiredCredentialReclaimGrace)
	v.SetDefault("jobs.expired-credential-reclaim.batch-size", 200)
	v.SetDefault("jobs.expired-credential-reclaim.dry-run", false)

	// Обновление снимка каталога модуля (#1816). Минута — верхняя граница
	// отставания снимка от базы, то есть столько снятый в работающем процессе
	// ресурс продолжает считаться живым. Величина выбрана по предмету: строки
	// каталога сегодня пишет только миграция, а административный путь снятия
	// заводится отдельной задачей; окно, измеряемое минутой, короче любого
	// осмысленного окна применения такого снятия.
	v.SetDefault("jobs.catalog-snapshot.refresh-interval", time.Minute)
	v.SetDefault("authn.sakey-max-ttl", 365*24*time.Hour)
	// Per-client access_token_lifespan for the SA-key OAuth2 client. Default 0 =
	// omit the field and inherit the provider-global TTL, so an existing
	// deployment is unchanged until its profile pins a value (values.prod.yaml
	// does). Override: KACHO_IAM_SAKEY_ACCESS_TOKEN_TTL.
	v.SetDefault("authn.sakey-access-token-ttl", time.Duration(0))
	// Sender-constrained (RFC 9449) tokens for SA keys. Binding is per-client
	// REGISTRATION metadata, so it takes effect only for keys issued after it is
	// enabled — pre-existing keys keep minting plain bearers until rotated.
	// Default false; the edge enforcement knob must be turned on only AFTER this
	// one, otherwise every existing service-account token is rejected.
	// Override: KACHO_IAM_SAKEY_BIND_DPOP.
	v.SetDefault("authn.sakey-bind-dpop", false)
	// bootstrap-mint — the cluster-admin token mint (#58). The signing key lives
	// in a k8s Secret, referenced BY ENV NAME here (never inlined in YAML). The
	// caller allow-list defaults to EMPTY = nobody may mint: the mint has no
	// default caller, so an operator must name the client-certificate SPIFFE SANs
	// explicitly (and an ENABLED mint with an empty list refuses to boot in
	// production — validate.go). Override —
	// KACHO_IAM_AUTHN__BOOTSTRAP_MINT__ALLOWED_CLIENT_SANS (comma-separated).
	v.SetDefault("authn.bootstrap-mint.signing-key-env", "KACHO_IAM_BOOTSTRAP_SA_PRIVATE_KEY_PEM")
	v.SetDefault("authn.bootstrap-mint.allowed-client-sans", []string{})

	// invite-mail — величины НАШЕГО отправителя письма приглашения (приёмка
	// ID-MAIL-1, Р23/Р25). Умолчания есть РОВНО У ДВУХ величин, и обе — про
	// ограниченность, а не про адрес: незаданный предел означал бы бесконечное
	// ожидание, незаданное число повторов — бесконечный повтор, то есть ровно те
	// дефекты, которые эти величины и снимают.
	//
	// У УЗЛА, АДРЕСА ОТПРАВИТЕЛЯ И УДОСТОВЕРЕНИЯ УМОЛЧАНИЙ НЕТ, и это решение
	// (Р3): величина, которую построение подставляет молча, предметом стража быть
	// не может — он зелен при любом входе, потому что незаданной она не бывает.
	// Пустой узел даёт наблюдаемый исход «настройка» на каждой попытке, а не
	// тихую отправку в никуда.
	//
	// Посадка полосы по умолчанию — шифрованная; незащищённой полосы разбор не
	// производит ни при каком входе (ban #16).
	// Override: KACHO_IAM_INVITE_MAIL__RELAY, __FROM, __FROM_NAME,
	// __USERNAME_ENV, __PASSWORD_ENV, __TLS_MODE, __CA_BUNDLE_FILE, __LOGIN_URL,
	// __ATTEMPT_TIMEOUT, __MAX_ATTEMPTS.
	v.SetDefault("invite-mail.relay", "")
	v.SetDefault("invite-mail.from", "")
	v.SetDefault("invite-mail.from-name", "")
	v.SetDefault("invite-mail.username-env", "")
	v.SetDefault("invite-mail.password-env", "")
	v.SetDefault("invite-mail.tls-mode", "starttls")
	v.SetDefault("invite-mail.ca-bundle-file", "")
	v.SetDefault("invite-mail.login-url", "")
	v.SetDefault("invite-mail.attempt-timeout", defaultInviteMailAttemptTimeout)
	v.SetDefault("invite-mail.max-attempts", defaultInviteMailMaxAttempts)

	// The external relations engine, the gateway-internal drainer, Enterprise SSO,
	// Governance, Federation/CAEP/ComplianceReport/Notify and the dead healthcheck
	// placeholder were all removed from this YAML (dead config). The drainer is
	// configured from KACHO_IAM_* env vars in the composition root; the engine no
	// longer exists at all, so it is configured nowhere. The
	// Prometheus metrics listener default is set above (api-server.metrics-endpoint).
}
