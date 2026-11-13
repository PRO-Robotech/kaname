// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
)

// Config — корневая структура конфигурации kaname.
//
// Иерархия YAML:
//
//	logger:        { level }
//	api-server:    { endpoint, internal-endpoint, graceful-shutdown }
//	repository:    { postgres }
//	authn:         { mode, domain, hooks, jwks, dpop } # режим, домен, обработчики, ключи JWKS и привязка DPoP
//
// Внутренний обработчик шлюза настраивается переменными KANAME_* в
// корне сборки (cmd/kaname), а не этим YAML.
//
// Каждый раздел имеет метки `mapstructure` (viper по умолчанию использует mapstructure для
// Unmarshal). Значения по умолчанию — в defaults.go.
type Config struct {
	AuthorityProtocol          AuthorityProtocolConfig           `mapstructure:"authority-protocol"`
	ModuleSeedInstaller        ModuleSeedInstallerConfig         `mapstructure:"moduleSeedInstaller"`
	RegistrationAccountWriters *RegistrationAccountWritersConfig `mapstructure:"registration-account-writers"`
	Logger                     LoggerConfig                      `mapstructure:"logger"`
	APIServer                  APIServerConfig                   `mapstructure:"api-server"`
	Repository                 RepositoryConfig                  `mapstructure:"repository"`
	AuthN                      AuthNConfig                       `mapstructure:"authn"`
	// Jobs — фоновые задания сервиса (задача kacho#1264). Секция заведена по
	// прецеденту сметателя целей nlb: интервал работы, удаляющей РЕСУРС
	// АРЕНДАТОРА по времени, живёт в конфигурации со стражем старта, а не
	// константой в композиционном корне.
	Jobs JobsConfig `mapstructure:"jobs"`
	// Retention — величины фоновой уборки таблиц, чей рост задаёт внешний
	// (задача kacho#1292). Порогов в ней нет: они вычисляются из `pkg/tokenpolicy`,
	// см. retention.go.
	Retention RetentionConfig `mapstructure:"retention"`
	// InviteMail — величины НАШЕГО отправителя письма приглашения (приёмка
	// ID-MAIL-1, Р23/Р25). Секция заведена своей, а не подсекцией `authn`:
	// предмет у неё исходящее соединение к чужому узлу, а не проверка
	// предъявленного. Величин две и они РАЗНЫЕ — предел времени на попытку и
	// число повторов; см. invite_mail.go.
	InviteMail InviteMailConfig `mapstructure:"invite-mail"`
	// Invite — величины ПРИГЛАШЕНИЯ как нашей сущности: срок строки, после
	// которого активация отвергается (приёмка ID-MAIL-1, §10 п. 22). Секция
	// отдельна от `invite-mail` намеренно: там величины ОТПРАВКИ письма, здесь —
	// свойства самой строки, и живут они независимо (приглашение без почты
	// по-прежнему заводится и по-прежнему истекает).
	Invite InviteConfig `mapstructure:"invite"`
	// Manifests — ДОСТАВКА манифестов модулей работающей службе (задача kacho#1875):
	// каталог, куда посадка их монтирует, и объявление того, что посадка на них
	// опирается. Секция заведена вперёд своих потребителей: пока каталог не
	// объявлен, служба поднимается ровно как прежде — см. manifests.go.
	Manifests ManifestsConfig `mapstructure:"manifests"`
	// AuthZ — величины СОБСТВЕННОЙ ДВЕРИ iam (пообъектный вопрос о доступе на
	// его собственных слушателях).
	//
	// Секция ВЕРНУЛАСЬ, и здесь стояло обратное. Прежняя редакция объясняла её
	// отсутствие тем, что обе прежние ручки — перечень типов реляционной формы и
	// признак теневой сверки — снялись вместе с внешним движком отношений.
	// Объяснение было верным для СВОЕГО предмета и перестало описывать
	// действительность, когда у секции появился новый: у двери есть окно отзыва,
	// и оно принадлежит оператору посадки, а не платформе.
	//
	// Ручка ровно одна, и она НЕ про производительность. Кешируется только
	// ПОЛОЖИТЕЛЬНЫЙ вердикт, поэтому срок жизни записи и ЕСТЬ время, в течение
	// которого субъект с уже отобранным правом продолжает проходить. Оставить
	// величину платформе значило бы, что на конкретном стенде это окно нельзя ни
	// сузить, ни даже прочитать в конфигурации.
	AuthZ AuthZConfig `mapstructure:"authz"`
	// OwnCeilings — СОБСТВЕННЫЕ ПОТОЛКИ службы доступа: сколько аккаунтов заводит
	// одна личность и сколько путей входа держит человек и машина (приёмка
	// `KAN-QUOTA-1`, `П25`; задача продукта kacho#2117). Перечень — таблица
	// `OwnCeilingKnobs` (own_ceilings.go).
	//
	// Секция заведена своей, а не подсекцией `authn`: предмет у неё — потолок
	// ЧИСЛА ресурсов, а не проверка предъявленного. Умолчания ни у одного нет
	// намеренно, и отказ старта при незаданной величине — не строгость, а
	// единственный способ, которым служба может иметь потолок, не имея
	// авторитета величин: спросить её больше не у кого. См. own_ceilings.go.
	OwnCeilings OwnCeilingsConfig `mapstructure:"own-ceilings"`
}

// AuthZConfig — окно вердикта собственной двери.
type AuthZConfig struct {
	// CacheTTL — срок жизни ПОЛОЖИТЕЛЬНОГО вердикта, то есть окно отзыва.
	// Умолчание ПРОЦЕССА 5s (`defaults.go`) — то же, что у остальных площадок
	// платформы (`pkg/authz.RevocationPolicy`), и оно закрывает НЕЗАДАННУЮ ручку.
	//
	// НЕПОЛОЖИТЕЛЬНАЯ величина роняет старт (`AuthZConfig.Validate`, задача
	// kacho#2307). Здесь стояло обратное — «ноль означает „взять умолчание политики“
	// ЯВНО», — и это объявляло законным ровно то состояние, в котором величина
	// перестаёт принадлежать оператору: конструктор кеша подставил бы умолчание
	// фундамента, а фундамент служба резолвит ПИНОМ, то есть чужой ревизией.
	// Умолчания у окна отзыва быть не может — тот же довод несёт дескриптор
	// носителя у шести соседних площадок.
	CacheTTL time.Duration `mapstructure:"cache-ttl"`
}

// LoggerConfig — раздел логирования.
type LoggerConfig struct {
	// Level — одно из FATAL|ERROR|WARN|INFO|DEBUG.
	Level string `mapstructure:"level"`
}

// SubscriptionConfig — посадка потока изменений ресурсов.
//
// Каждый поток держит СВОЁ соединение вне пула, поэтому потолок числа потоков —
// не вкус, а арифметика: число реплик × потолок + непуловые соединения обязаны
// помещаться в предел владельца базы. Превышение отвечает ОТКАЗОМ, а не
// молчаливой очередью: очередь превратила бы исчерпание в неограниченное
// ожидание, неотличимое для клиента от «событий нет».
type SubscriptionConfig struct {
	// MaxStreams — потолок числа ОДНОВРЕМЕННЫХ потоков процесса.
	MaxStreams int `mapstructure:"max-streams"`
	// StreamBudget — срок жизни одного потока. По истечении поток закрывается
	// ЧИСТО, а не ошибкой: клиент возобновляется со своей позиции, а обрыв
	// ошибкой он прочёл бы как сетевой сбой.
	StreamBudget time.Duration `mapstructure:"stream-budget"`
	// IdlePoll — холостой перепрос. Он не «на всякий случай»: ОТКАТИВШИЙСЯ
	// писатель уведомления не шлёт, и подтверждение горизонта приезжает именно
	// им.
	IdlePoll time.Duration `mapstructure:"idle-poll"`
}

// APIServerConfig — раздел api-server.
//
// Endpoint / InternalEndpoint принимают два формата:
//   - `tcp://0.0.0.0:9090` (полная форма URL, рекомендуется);
//   - `9090` (прежняя форма: только порт; сохранена для совместимости
//     со старыми values.yaml, см. listenAddress в load.go).
type APIServerConfig struct {
	Endpoint         string        `mapstructure:"endpoint"`
	InternalEndpoint string        `mapstructure:"internal-endpoint"`
	GracefulShutdown time.Duration `mapstructure:"graceful-shutdown"`
	// MetricsEndpoint — слушатель HTTP Prometheus /metrics. ОТДЕЛЬНЫЙ
	// внутренний порт кластера (по умолчанию `tcp://0.0.0.0:9095`), никогда не публичная
	// поверхность gRPC арендатора: размещение реестра там раскрыло бы внутреннюю
	// кардинальность. Пустое значение отключает слушатель метрик.
	MetricsEndpoint string `mapstructure:"metrics-endpoint"`
	// RegistryToken — слушатель HTTP сервера аутентификации Docker Registry v2 `/iam/token`.
	// ОТДЕЛЬНЫЙ, доступный ИЗВНЕ порт без шифрования (по умолчанию
	// `tcp://0.0.0.0:9096`; TLS завершается на ingress, как у слушателя
	// метрик): клиенты docker обращаются к `/iam/token` через край, чтобы
	// обменять ключ SA на краткоживущий JWT идентичности. Отличается от внутренних
	// слушателей метрик (:9095) и набора ключей (:9097). Пустой
	// адрес отключает его.
	RegistryToken RegistryTokenConfig `mapstructure:"registry-token"`
	// RESTEndpoint — собственный ПУБЛИЧНЫЙ REST-фронт службы.
	//
	// Пока служба стоит за краем платформы, её HTTP-поверхность принадлежит
	// краю. Вынесенная отдельным продуктом, края она не имеет по построению —
	// и её REST обязан существовать сам.
	//
	// УМОЛЧАНИЯ НЕТ намеренно, и это отличает ребро от трёх соседних. У тех
	// адрес приходит умолчанием процесса и потому непуст всегда: профиль,
	// умолчавший о них, поднимал их открытым текстом, и заметить это было
	// неоткуда. Здесь пустой адрес означает «фронт не поднят», и это
	// НАЗЫВАЕТСЯ — осью самоотчёта с объяснением, что именно не обслуживается.
	// Subscription — ВЕЛИЧИНЫ ПОСАДКИ потока изменений ресурсов.
	//
	// Они приезжают из объявления сервиса и в механизме умолчаний не имеют:
	// фундамент отвергает нулевые, потому что величина посадки, которую никто не
	// выбирал, не обсуждаема и не сужаема. Умолчания стоят ЗДЕСЬ, где их видит
	// оператор, а не внутри общего сервера, где их не видит никто.
	Subscription SubscriptionConfig `mapstructure:"subscription"`
	RESTEndpoint string             `mapstructure:"rest-endpoint"`
	// InternalRESTEndpoint — собственный ВНУТРЕННИЙ REST-фронт службы.
	//
	// Отдельный слушатель, а не разбор пути на общем: раздельность фронтов есть
	// свойство СОКЕТА. Тогда «внутреннее не опубликовано» значит «недосягаемо»,
	// и это доказуемо снаружи одним обращением, а не чтением условия.
	//
	// Умолчания нет по той же причине, что у публичного.
	InternalRESTEndpoint string `mapstructure:"internal-rest-endpoint"`
	// JWKSProxy — ВНУТРЕННИЙ слушатель HTTP публикации набора ключей кластера (по умолчанию
	// `tcp://0.0.0.0:9097`). Запись у него ОДНА — НАША, проекция ключницы iam по
	// `authn.token-signing.key-set-path`; запись зеркала набора прежнего
	// провайдера снята вместе с ним (kaname#361). Плоскость данных берёт ключи
	// проверки у iam.
	//
	// Разбор — в шапке jwks_proxy.go, второго места об этом предмете здесь нет.
	//
	// Обслуживается ТОЛЬКО внутренним Service `kaname-internal` кластера (никогда
	// извне, ban #6) с односторонним серверным TLS. Пустое значение отключает его.
	JWKSProxy JWKSProxyConfig `mapstructure:"jwks-proxy"`

	// RateLimit — ПОТОЛОК ТЕМПА и ОДНОВРЕМЕННОСТИ на вызывающего, по одному
	// набору на слушатель.
	//
	// У iam он значит больше, чем у соседей: iam стоит на пути запроса ВСЕХ
	// остальных доменов (решение о доступе спрашивают у него на каждом RPC),
	// поэтому неограниченный поток одного вызывающего сюда бьёт не по одному
	// сервису, а по всей платформе.
	//
	// Молчание посадки означает ПОЛ ПЛАТФОРМЫ
	// (`grpcsrv.PlatformPublicAdmission` / `PlatformInternalAdmission`), а не
	// ноль: ноль механизм читает как «не ограничиваем», и слушатель выглядел бы
	// защищённым, ни разу не отказав. Посадка вправе назвать свои величины, но
	// только ВЕСЬ набор из четырёх осей — частичное объявление отвергается
	// стартом с именем слушателя.
	RateLimit RateLimitConfig `mapstructure:"rate-limit"`
	// RESTLimits — потолки размера тела и одновременности собственного
	// публичного REST-фронта (kaname#990). Разбор — в шапке rest_limits.go.
	RESTLimits RESTLimitsConfig `mapstructure:"rest-limits"`
	// LoginLaneEndpoint — адрес HTTP-слушателя полосы входа паролем (Ф3,
	// kacho#1269): глаголы формы (перечень — `loginlanehttp.Paths()`),
	// ретранслируемые краем; TLS взаимный, допуск — ровно край. Пустой —
	// слушатель не поднимается; под посадкой `own` пустой — отказ старта.
	LoginLaneEndpoint string `mapstructure:"login-lane-endpoint"`
}

// RateLimitConfig — величины допуска обоих слушателей в том виде, в каком их
// объявляет файл настроек.
//
// Структура ручек — общая с фундаментом (`grpcsrv.AdmissionKnobs`): те же
// четыре оси читают три семейства настроек платформы, и три копии тегов
// разъехались бы на первой же новой оси — молча, потому что незнакомый ключ
// viper игнорирует.
type RateLimitConfig struct {
	// Public — величины публичного слушателя, на ПРИНЦИПАЛА.
	Public grpcsrv.AdmissionKnobs `mapstructure:"public"`
	// Internal — величины внутреннего слушателя, на ЛИЧНОСТЬ СЕРТИФИКАТА.
	Internal grpcsrv.AdmissionKnobs `mapstructure:"internal"`
}

// RepositoryConfig — раздел repository. Только Postgres (ветвления по типу хранилища
// никогда не было; неиспользуемая ручка `type` снята).
type RepositoryConfig struct {
	Postgres PostgresConfig `mapstructure:"postgres"`
}

// PostgresConfig — раздел repository.postgres.
//
// URL — стандартный DSN postgres://user:pass@host:port/db (основная база).
// SlaveURL — DSN реплики чтения (необязателен).
// MaxConns — предел соединений pgxpool (0 = по умолчанию в pgx).
//
//	ReplicaBudget    — под сколько реплик рассчитана посадка (см. PostgresConfig).
//
// SSLMode — disable|require|verify-ca|verify-full (проверяется в Validate).
// PasswordFromEnv — имя переменной окружения, откуда читается пароль для
//
//	подстановки в URL и SlaveURL. По умолчанию — KANAME_DB_PASSWORD.
type PostgresConfig struct {
	URL      string `mapstructure:"url"`
	SlaveURL string `mapstructure:"slave-url"`
	MaxConns int    `mapstructure:"max-conns"`

	// ReplicaBudget — сколько реплик этой посадки могут работать ОДНОВРЕМЕННО.
	//
	// Служба не знает этого о себе и знать не обязана: под сколько реплик её
	// раскладывают — свойство раскладки, а не процесса. Поэтому величину
	// СООБЩАЮТ, и сообщает её тот же шаблон, который рендерит число реплик, —
	// одно значение, два места применения, разойтись им негде.
	//
	// Нужна затем, что предел соединений у базы ОБЩИЙ на все реплики, а пул
	// объявлен на ОДНУ. Произведение не записано нигде, и потому расхождение
	// между обещанным и принимаемым не видно ни в одном файле по отдельности
	// (загрузочный страж — `assertConnBudgetFits` в корне сборки).
	ReplicaBudget   int    `mapstructure:"replica-budget"`
	SSLMode         string `mapstructure:"ssl-mode"`
	PasswordFromEnv string `mapstructure:"password-from-env"`
}

// AuthNConfig — раздел authn.
//
// Mode — общий режим сервиса (см. mode.go).
//
// Основные поля AuthN:
//
//	Domain                — доменное имя посадки, объявленное оператором.
//	                        Умолчания НЕТ — незаданное значение доезжает
//	                        до стража, а не замещается построением
//	                        (см. ResolveDomain; свойство держит проба
//	                        TestDomainHasNoCompiledInDefault). Из него
//	                        сборка состава утверждений выводит адресата.
//	JWKSEncryptionKeyHex  — 32-байтовый ключ ОБЁРТКИ приватной половины
//	                        подписного ключа, в hex (64 символа). Ею
//	                        оборачивается приватная половина в ключнице
//	                        (задача kacho#897); ручка об этом предмете в дереве
//	                        ОДНА, и её значение меняет исход старта — см.
//	                        validateProductionAuthNSecrets.
//	SAKeyRedactGrace      — задержка между Done-ом Issue-Operation и затиранием
//	                        одноразового private_key_pem в её response. Даёт
//	                        поллящему клиенту окно, чтобы забрать ключ до вычистки.
//
// По умолчанию 120с; переопределение KANAME_SAKEY_REDACT_GRACE.
//
//	UserTokenRedactGrace  — то же для UserTokenService.Issue (персональные токены
//	                        пользователя). По умолчанию 120с; переопределение
//	                        KANAME_USERTOKEN_REDACT_GRACE.
//	SAKeyDefaultTTL       — срок жизни SA-ключа, когда вызывающий не передал
//	                        ttl_seconds. Машинный принципал освобождён от
//	                        усиленного входа (у машины нет второго фактора) —
//	                        это защитимо лишь пока сам ключ ограничен по времени,
//	                        поэтому умолчание конечно, а не «никогда».
//
// По умолчанию 2160ч (90д); переопределение KANAME_SAKEY_DEFAULT_TTL.
//
//	SAKeyMaxTTL           — включительный потолок ttl_seconds. Запрос сверх него
//	                        отвергается InvalidArgument ДО всякой записи.
//
// По умолчанию 8760ч (365д); переопределение KANAME_SAKEY_MAX_TTL.
//
//		SAKeyBindDPoP         — требование sender-constrained токенов (RFC 9449
//		                        `cnf.jkt`) на РЕГИСТРАЦИИ клиента SA-ключа у внешнего
//		                        поставщика. ЧИТАТЕЛЯ НЕТ: регистрации выдача больше не
//		                        заводит ни на одной посадке (kaname#362). Страж старта
//		                        отвергает ручку на посадке с токен-эндпоинтом
//		                        (validateMachineTokenBinding); без эндпоинта ключевая
//		                        пара не выдаётся вовсе, и связанного-по-убеждению ключа
//	                        не возникает. По умолчанию false; переопределение KANAME_SAKEY_BIND_DPOP.
//
// SAKeyAccessTokenTTL — значение access_token_lifespan каждого клиента при РЕГИСТРАЦИИ
//
//	клиента SA-ключа у внешнего поставщика. ЧИТАТЕЛЯ НЕТ с
//	kaname#362 — регистрации нет; срок наших токенов
//	задаёт authn.client-token.token-ttl. Ручка остаётся,
//	пока её эмитирует чарт платформы (kacho:
//	deploy/helm/umbrella/charts/kaname/templates/deployment.yaml,
//	KANAME_SAKEY_ACCESS_TOKEN_TTL): снятая здесь раньше,
//	она перестала бы читаться без единого слова. Снимается
//	тем изменением, которым её перестанет эмитировать чарт.
//
// Переопределение KANAME_SAKEY_ACCESS_TOKEN_TTL.
type AuthNConfig struct {
	Mode                    Mode   `mapstructure:"mode"`
	Domain                  string `mapstructure:"domain"`
	JWKSEncryptionKeyHex    string `mapstructure:"jwks-encryption-key-hex"`
	JWKSEncryptionKeyHexEnv string `mapstructure:"jwks-encryption-key-hex-env"`
	// SecondFactorEncryptionKeyHex — перечень ключей ОБЁРТКИ секретов второго
	// фактора (Ф12 Р2, kacho#1281): первый оборачивает, все открывают. СВОЯ
	// ручка, а не ручка подписного ключа: предмет другой (секретов много, по
	// одному на человека; радиус компрометации — вход людей), и смена одного
	// ключа не обязана останавливать другой. Обе половины повторяют форму
	// соседней: значением либо именем переменной окружения.
	SecondFactorEncryptionKeyHex    string `mapstructure:"second-factor-encryption-key-hex"`
	SecondFactorEncryptionKeyHexEnv string `mapstructure:"second-factor-encryption-key-hex-env"`
	// SelfServiceFreshness — окно свежести правки своих данных (Ф1 §4.1 «15
	// мин», Ф11 Р6 — от момента последнего предъявления; Ф12 Р8): заведение и
	// подтверждение второго фактора, заведение первого пароля, запрос смены
	// адреса почты, регистрация и снятие ключа доступа, выход из выбранной
	// сессии и из всех, кроме текущей, требуют, чтобы с последнего предъявления
	// прошло не больше окна; окно одно на все эти глаголы. Это девять путей
	// (перечень — таблицы `docs/content/api/auth-lane.mdx`):
	// `POST /iam/v1/auth/password/enroll`,
	// `POST /iam/v1/auth/second-factor/enroll`,
	// `POST /iam/v1/auth/second-factor/confirm`,
	// `POST /iam/v1/auth/email-change`,
	// `POST /iam/v1/users/{user_id}/accessKeys:beginRegistration`,
	// `POST /iam/v1/users/{user_id}/accessKeys`,
	// `DELETE /iam/v1/users/{user_id}/accessKeys/{access_key_id}`,
	// `POST /iam/v1/auth/sessions/end`, `POST /iam/v1/auth/sessions/end-others`.
	// Тем же окном ограничен срок неподтверждённого заведения второго
	// фактора. Умолчания нет: величина объявляется профилем.
	SelfServiceFreshness time.Duration `mapstructure:"self-service-freshness"`
	// TokenSigning — СВОЯ чеканка токенов (задача kacho#897): издатель, алгоритм,
	// перечень допустимых алгоритмов приёма, путь нашей записи публикуемого
	// набора и срок ключа. Пока выключена, её настройки не требуются; будучи
	// включённой, требует их все — незаданное здесь означает «не сужаем».
	TokenSigning TokenSigningConfig `mapstructure:"token-signing"`
	// ClientToken — токен-эндпоинт платформы (задача kacho#898): приём вида выдачи
	// «учётные данные клиента» с аутентификацией подписанным утверждением.
	// Пока выключен, его настройки не требуются; будучи включённым, требует их
	// все — и требует включённой своей чеканки, потому что выпускает НАШИМ
	// подписантом и объявляет НАШЕГО издателя ожидаемым адресатом утверждения.
	ClientToken ClientTokenConfig `mapstructure:"client-token"`
	// PresentedCredential — приём удостоверения, ПРЕДЪЯВЛЕННОГО самим
	// вызывающим, на публичном слушателе (задача продукта kacho#2077).
	//
	// Без него личность на публичном слушателе производится ровно двумя
	// способами, и оба предполагают нашу инфраструктуру рядом: клиентский
	// сертификат проверенного пира и личность, переданная разрешённым
	// отправителем. В чужом облаке нет ни того, ни другого — арендатору нечем
	// назваться.
	PresentedCredential  PresentedCredentialConfig `mapstructure:"presented-credential"`
	SAKeyRedactGrace     time.Duration             `mapstructure:"sakey-redact-grace"`
	UserTokenRedactGrace time.Duration             `mapstructure:"usertoken-redact-grace"`
	SAKeyDefaultTTL      time.Duration             `mapstructure:"sakey-default-ttl"`
	SAKeyMaxTTL          time.Duration             `mapstructure:"sakey-max-ttl"`
	SAKeyAccessTokenTTL  time.Duration             `mapstructure:"sakey-access-token-ttl"`
	SAKeyBindDPoP        bool                      `mapstructure:"sakey-bind-dpop"`
	// BootstrapMint — проверка вызывающего и источник ключа для
	// InternalBootstrapTokenService.MintBootstrapToken.
	BootstrapMint BootstrapMintConfig `mapstructure:"bootstrap-mint"`
	// Login — полоса входа паролем и наша сессия (Ф3, kacho#1269): срок и домен
	// печенья, частота, политика пароля, ручка «что писать», ёмкость. Ни одна
	// величина не подставляется молча; требуются под посадкой `own`.
	Login LoginLaneConfig `mapstructure:"login"`
	// Registration — регистрация нашей полосой (Ф4): потолок темпа заведения.
	Registration RegistrationConfig `mapstructure:"registration"`
	// AccessKeys — привязка ключей доступа (Ф7, kacho#1273): имя доверяющей
	// стороны, перечень происхождений, перечень алгоритмов. Величины посадки
	// `own` без умолчания; пустой перечень происхождений — «никого».
	AccessKeys AccessKeysConfig `mapstructure:"access-keys"`
	// Ceremony — сроки артефактов собственной церемонии (kaname#318): срок кода
	// авторизации и срок семейства токенов обновления. Величины посадки `own`
	// без умолчания, не выше потолков фундамента.
	Ceremony CeremonyConfig `mapstructure:"ceremony"`
	// TrustedForwarderSANs — ТОЧНЫЕ URI SPIFFE SAN сертификатов клиентов, которым разрешено
	// ПЕРЕДАВАТЬ идентичность пользователя (метаданные `x-kacho-principal-*`) в iam. Подаются
	// в grpcsrv.WithTrustedForwarders на ОБОИХ слушателях gRPC
	// (cmd/kaname/serve.go identityUnary/identityStream).
	//
	// Почему это ручка, а не константа: контракт corelib
	// (pkg/grpcsrv principalIsTrusted) сужает круг отправителей ТОЛЬКО при
	// непустом списке; при пустом он отвечает «доверен» ЛЮБОМУ соседу,
	// прошедшему проверку сертификата клиента. Оба порта gRPC — обычные Service
	// внутри пространства имён; сертификат клиента каждого соседа выпускается тем же
	// внутренним центром, поэтому пустой список означает, что любой pod может передать
	// заголовки идентичности жертвы и заставить iam решать от её имени (вся поверхность
	// CRUD арендатора на :9090, включая выпуск учётных данных). Сетевое положение не
	// заменяет проверку: единственная NetworkPolicy, выбирающая pod iam, покрывает внутренний
	// порт и выключена вне производственного режима.
	//
	// Формат: значения через запятую при переопределении переменной
	// KANAME_AUTHN__TRUSTED_FORWARDER_SANS; список YAML под
	// authn.trusted-forwarder-sans.
	//
	// Пустой список допустим ТОЛЬКО в dev (внутрипроцессные фикстуры); в любом производственном режиме
	// Validate отказывает в запуске (отказ по умолчанию, как в geo/compute/nlb/storage/
	// registry).
	TrustedForwarderSANs []string `mapstructure:"trusted-forwarder-sans"`

	// TrustAnyForwarder — ЯВНЫЙ опт-ин «круг не сужаем», действующий ТОЛЬКО вне
	// боевого режима. Нужен для локальных in-process фикстур, где ни сертификатов,
	// ни шлюза нет.
	//
	// Он существует потому, что стража круга срабатывает на ЛЮБОМ старте, а не
	// только в боевом режиме: контроль, чья ветка на локальном стенде не
	// исполняется ни разу, обнаруживает «забыл выставить круг» только на боевом
	// профиле, где цена ошибки максимальна. Оставленный незаданным (false) = отказ
	// старта на пустом круге. В боевом режиме НЕ действует — иначе это была бы
	// ручка, снимающая защиту на развёрнутом стенде.
	TrustAnyForwarder bool `mapstructure:"trust-any-forwarder"`

	// TrustDomainName — ДОМЕН ДОВЕРИЯ установки: то, чьи сертификаты она признаёт своими.
	//
	// Круг отправителей выше называет, КОМУ позволено говорить за пользователя;
	// домен отвечает на предыдущий вопрос — чьи вообще предъявители наши. Пока он
	// был скомпилирован, установка меняла его только пересборкой: сертификаты
	// выпускаются под доменом из величины профиля, а принимающая сторона читала
	// литерал, и расходились они МОЛЧА — законный отправитель переставал
	// опознаваться, а отказ выглядел как вызов без личности.
	//
	// Умолчания нет намеренно: непустое умолчание сделало бы контроль на вид
	// включённым и увело бы установку, забывшую назвать свой домен, в чужой.
	// Пустая величина — отказ старта (Validate), а не «принимаем любой».
	//
	// ENV `KANAME_AUTHN__TRUST_DOMAIN`, ключ YAML `authn.trust-domain`.
	TrustDomainName string `mapstructure:"trust-domain"`

	// ModuleIdentities — ЛИЧНОСТИ МОДУЛЕЙ установки (kaname#984): записи
	// `<пространство>/<учётка>=<профиль>`.
	//
	// Домен выше отвечает, чьи предъявители наши; перечень — кто из наших
	// модуль и что ему позволено звать. Модулем признаётся ТОЛЬКО объявленная
	// пара: прежде им был любой проверенный лист домена с приставкой модулей в
	// любом пространстве, и владелец постороннего пространства, получивший лист
	// на учётку нужного имени, становился модулем. Профиль называет закрытый
	// перечень методов внутреннего слушателя (`authzguard.ProfileMethods`).
	//
	// Умолчания нет: перечень — факт установки, и написанный здесь называл бы
	// модули, которых у неё может не быть. Пустой перечень в боевом режиме —
	// отказ старта (по нему не признаётся никто, край в том числе);
	// неразбираемая запись — отказ старта в любом режиме.
	//
	// ENV `KANAME_AUTHN__MODULE_IDENTITIES` (через запятую), ключ YAML
	// `authn.module-identities` (список).
	ModuleIdentities []string `mapstructure:"module-identities"`

	// ClientIssuers — ДОВЕРЕННЫЕ УДОСТОВЕРЯЮЩИЕ ЦЕНТРЫ установки поимённо
	// (kaname#988): записи `<имя>=<путь к PEM с сертификатами центра>`.
	//
	// Личность модуля называет центр, который вправе выпускать её лист
	// (`…=<профиль>@<имя>`), и лист признаётся, только если его проверенная
	// цепочка оканчивается якорем именно этого центра. Без привязки доверие ко
	// всем центрам пула слушателя общее: лист с допустимым SAN признаётся, какой
	// бы из них его ни выпустил. Файл центра обязан входить и в пул клиентских
	// центров слушателя — иначе лист этого центра не проверится вовсе.
	//
	// Умолчания нет. В боевом режиме каждая личность обязана быть привязана
	// (отказ старта); неразбираемая запись и нечитаемый файл — отказ старта в
	// любом режиме.
	//
	// ENV `KANAME_AUTHN__CLIENT_ISSUERS` (через запятую), ключ YAML
	// `authn.client-issuers` (список).
	ClientIssuers []string `mapstructure:"client-issuers"`
}

// LoadModuleRoster — перечень личностей модулей, который уезжает во все пути
// признания вызывающего обоих слушателей и HTTP-поверхностей, вместе с
// прочитанными центрами и причиной, по которой он не собрался. Читает файлы
// центров: его зовёт корень при подъёме, ОДИН раз и до сборки служб, а не страж
// настройки, который судит профиль на любой машине.
//
// Формы, глотающей ошибку, нет намеренно (kaname#987): нулевой перечень значит
// разное у потребителей — политике вызывающего «модуль никто», то есть отказ,
// обработчику внутреннего Check «сужать некого», то есть привязка плоскости
// данных к домену не применяется. Нулевое значение мимо ошибки открыло бы
// второму потребителю то, что первый закрывает.
func (a AuthNConfig) LoadModuleRoster() (moduleidentity.Roster, error) {
	entries, err := clientIssuerEntries(a.ClientIssuers)
	if err != nil {
		return moduleidentity.Roster{}, err
	}
	issuers, err := loadClientIssuers(entries)
	if err != nil {
		return moduleidentity.Roster{}, err
	}
	return moduleidentity.ParseWithIssuers(a.ModuleIdentities, issuers)
}

// clientIssuer — запись доверенного центра: имя и путь к его PEM.
type clientIssuer struct{ name, path string }

// clientIssuerEntries разбирает записи `<имя>=<путь>` без чтения файлов. Имя
// объявляется один раз.
func clientIssuerEntries(raw []string) ([]clientIssuer, error) {
	var out []clientIssuer
	seen := map[string]bool{}
	for _, r := range raw {
		entry := strings.TrimSpace(r)
		if entry == "" {
			continue
		}
		name, path, ok := strings.Cut(entry, "=")
		name, path = strings.TrimSpace(name), strings.TrimSpace(path)
		if !ok || name == "" || path == "" {
			return nil, fmt.Errorf("client issuer %q: write it as <name>=<path to the PEM of the authority>", entry)
		}
		if seen[name] {
			return nil, fmt.Errorf("client issuer %q is declared twice", name)
		}
		seen[name] = true
		out = append(out, clientIssuer{name: name, path: path})
	}
	return out, nil
}

// loadClientIssuers читает центры: каждый файл — PEM хотя бы с одним
// сертификатом.
func loadClientIssuers(entries []clientIssuer) (moduleidentity.IssuerSet, error) {
	out := moduleidentity.IssuerSet{}
	for _, e := range entries {
		// #nosec G304 -- путь из настройки оператора (смонтированный пакет центра),
		// а не вход запроса.
		pemBytes, err := os.ReadFile(e.path)
		if err != nil {
			return nil, fmt.Errorf("client issuer %q: read %q: %w", e.name, e.path, err)
		}
		var certs []*x509.Certificate
		for rest := pemBytes; len(rest) > 0; {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("client issuer %q: parse a certificate of %q: %w", e.name, e.path, err)
			}
			certs = append(certs, c)
		}
		if len(certs) == 0 {
			return nil, fmt.Errorf("client issuer %q: no certificate in %q", e.name, e.path)
		}
		out[e.name] = certs
	}
	return out, nil
}

// TrustDomain — домен доверия, который РЕАЛЬНО уезжает в пару звеньев извлечения
// личности на обоих слушателях.
//
// Единственный источник этой величины на процесс: проводка, стража старта и
// самоотчёт о посадке читают ОДИН объект и спрашивают его ОДИН предикат. Значит
// «страж пропустил» ⟺ «домен реально объявлен» — по построению, а не потому, что
// три автора написали одинаковые тела.
//
// Приведение написанного оператором (пробелы, схема, косые черты) живёт в
// конструкторе типа и здесь не повторяется: два места об одном предмете
// расходятся молча. См. grpcsrv.NewTrustDomain.
func (a AuthNConfig) TrustDomain() grpcsrv.TrustDomain {
	return grpcsrv.NewTrustDomain(a.TrustDomainName)
}

// TrustedForwarders — круг отправителей, РЕАЛЬНО доходящий до
// grpcsrv.WithTrustedForwarders на обоих слушателях.
//
// Единственный источник значения в процессе: сборка (cmd/kaname/serve.go),
// проверка при старте (validateProductionTrustedForwarders) и отчёт о режиме запуска
// (cmd/kaname/bootposture.go) читают этот объект и спрашивают ЕГО ЕДИНСТВЕННЫЙ
// предикат. Поэтому «проверка пройдена» ⟺ «круг действительно сужен» по
// построению, а не случайному совпадению трёх отдельно написанных реализаций.
//
// Нормализация круга (пустые элементы, пробелы по краям,
// повторы) находится в конструкторе типа и здесь не повторяется: два
// места об одном предмете молча расходятся. См.
// grpcsrv.NewTrustedForwarders.
func (a AuthNConfig) TrustedForwarders() grpcsrv.TrustedForwarders {
	return grpcsrv.NewTrustedForwarders(a.TrustedForwarderSANs...)
}

// BootstrapMintConfig — раздел authn.bootstrap-mint: неинтерактивный
// выпуск токена администратора кластера (#58).
//
// Выпускается Bearer, подписанный нашим подписантом, для ServiceAccount кластера с `system_admin`.
// Проверить его отношением ReBAC нельзя (он нужен для получения
// ПЕРВОГО токена, когда отношений ещё нет), а сетевое положение НЕ должно быть основанием,
// поэтому учётные данные — СЕРТИФИКАТ КЛИЕНТА ВЫЗЫВАЮЩЕГО: лишь перечисленные здесь SPIFFE
// SAN могут вызывать метод; на :9091 это обеспечивает authzguard.CallerPolicy.
//
// Два уровня отказа по умолчанию:
//   - При работе пустой разрешающий список отвергает всех вызывающих (вызывающего
//     по умолчанию нет), как в dev, так и в производственном режиме;
//   - При старте ВКЛЮЧЁННЫЙ выпуск (ключ подписи есть) с пустым разрешающим списком
//     ОТКАЗЫВАЕТ В ЗАПУСКЕ в производственном режиме (Validate), поэтому небезопасная комбинация
//     недостижима из-за пропуска настройки (правило ядра #16).
type BootstrapMintConfig struct {
	// SigningKeyEnv — имя переменной окружения с закрытым ключом начальной SA в формате
	// PEM (поставляется из Secret k8s; никогда в YAML). ПУСТОЕ значение этой
	// переменной означает, что выпуск ВЫКЛЮЧЕН: сценарий отказывает по умолчанию с
	// UNAVAILABLE, а проверка при старте не применяется. По умолчанию:
	// KANAME_BOOTSTRAP_SA_PRIVATE_KEY_PEM.
	SigningKeyEnv string `mapstructure:"signing-key-env"`
	// AllowedClientSANs — ТОЧНЫЕ URI SPIFFE SAN сертификатов клиентов, которым разрешён
	// вызов MintBootstrapToken (например,
	// `spiffe://kacho.cloud/ns/kacho/sa/kacho-bootstrap-seeder`). Пусто → никто
	// не может выпускать токены. Переменная окружения: значения через запятую в
	// KANAME_AUTHN__BOOTSTRAP_MINT__ALLOWED_CLIENT_SANS.
	AllowedClientSANs []string `mapstructure:"allowed-client-sans"`
}

// defaultBootstrapSigningKeyEnv — переменная окружения, из которой корень сборки всегда
// читал ключ начальной SA.
const defaultBootstrapSigningKeyEnv = "KANAME_BOOTSTRAP_SA_PRIVATE_KEY_PEM"

// ResolveSigningKeyEnv возвращает ИМЯ переменной окружения с ключом начальной подписи,
// при отсутствии настройки выбирая документированное значение по умолчанию.
func (b BootstrapMintConfig) ResolveSigningKeyEnv() string {
	if name := strings.TrimSpace(b.SigningKeyEnv); name != "" {
		return name
	}
	return defaultBootstrapSigningKeyEnv
}

// ResolveSigningKeyPEM читает PEM закрытого ключа начальной SA из переменной окружения.
// Пусто → выпуск отключён. Читается только os.Getenv (без иных побочных эффектов),
// как в других методах Resolve*; ЗНАЧЕНИЕ никогда не попадает в журнал или
// сообщение ошибки.
func (b BootstrapMintConfig) ResolveSigningKeyPEM() string {
	return strings.TrimSpace(os.Getenv(b.ResolveSigningKeyEnv()))
}

// Enabled сообщает, настроен ли выпуск вообще (присутствует ключ подписи).
func (b BootstrapMintConfig) Enabled() bool { return b.ResolveSigningKeyPEM() != "" }

// AllowedSANs возвращает разрешающий список без пустых элементов; пустой результат означает
// «запретить всем», ровно как требует CallerPolicy.
func (b BootstrapMintConfig) AllowedSANs() []string {
	out := make([]string, 0, len(b.AllowedClientSANs))
	for _, san := range b.AllowedClientSANs {
		if s := strings.TrimSpace(san); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// schemaOptionsParam — закодированный для URL параметр libpq `options=-c search_path=…`.
// Автоматически добавляется к baseDSN, чтобы каждое соединение (pgxpool, выделенный
// pgx.Conn для LISTEN, goose через database/sql) видело таблицы kaname под
// неквалифицированными именами.
//
// search_path имеет значение "kaname, public":
// - `kaname` первым — наши таблицы;
// - `public` вторым — встроенные объекты / расширения Postgres.
const schemaOptionsParam = "options=-c%20search_path%3Dkaname%2Cpublic"

// baseDSN — стандартный DSN postgres без параметров pgxpool; используется и
// pgxpool, и database/sql.Open("pgx").
func (c Config) baseDSN() string {
	return c.composeDSN(c.Repository.Postgres.URL)
}

// composeDSN добавляет недостающие параметры libpq к исходному DSN: `sslmode=<mode>`
// и `options=-c search_path=kaname,public`. Если параметр уже
// присутствует в исходном URL, не заменяем его (проще переопределять через окружение/yaml).
func (c Config) composeDSN(raw string) string {
	if raw == "" {
		return ""
	}
	mode := c.Repository.Postgres.SSLMode
	if mode == "" {
		mode = "disable"
	}
	if !dsnHas(raw, "sslmode=") {
		sep := "?"
		if dsnHas(raw, "?") {
			sep = "&"
		}
		raw = raw + sep + "sslmode=" + mode
	}
	if !dsnHas(raw, "options=") && !dsnHas(raw, "options%3D") {
		sep := "?"
		if dsnHas(raw, "?") {
			sep = "&"
		}
		raw = raw + sep + schemaOptionsParam
	}
	return raw
}

// DSN — строка соединения для pgxpool (поддерживает pool_max_conns).
// НЕ использовать для database/sql.Open("pgx"): неизвестный серверный параметр приводит к FATAL.
func (c Config) DSN() string {
	dsn := c.baseDSN()
	if dsn == "" {
		return ""
	}
	if c.Repository.Postgres.MaxConns > 0 {
		dsn += fmt.Sprintf("&pool_max_conns=%d", c.Repository.Postgres.MaxConns)
	}
	return dsn
}

// SingleConnDSN — строка подключения для ВЫДЕЛЕННОГО соединения вне пула.
//
// Отличается от [Config.DSN] ровно отсутствием параметров пула, и это не
// оформление: вне пула `pool_max_conns` — неизвестный серверу параметр, и
// подключение с ним падает FATAL. Отказ наступил бы у КАЖДОЙ подписки в бою, а
// не на сборке, поэтому композиционный корень сверяет строку стражем.
func (c Config) SingleConnDSN() string { return c.baseDSN() }

// SlaveDSN — строка соединения пула реплики чтения. Пустая
// строка → реплика не настроена, вызывающий использует основную базу.
func (c Config) SlaveDSN() string {
	slaveRaw := c.Repository.Postgres.SlaveURL
	if slaveRaw == "" || slaveRaw == c.Repository.Postgres.URL {
		return ""
	}
	dsn := c.composeDSN(slaveRaw)
	if dsn == "" {
		return ""
	}
	if c.Repository.Postgres.MaxConns > 0 {
		dsn += fmt.Sprintf("&pool_max_conns=%d", c.Repository.Postgres.MaxConns)
	}
	return dsn
}

// MigrateDSN — строка соединения для goose/database/sql (без
// pool_max_conns). Всегда указывает на основную базу: goose не должен писать в
// реплику.
func (c Config) MigrateDSN() string { return c.baseDSN() }

func dsnHas(dsn, frag string) bool {
	for i := 0; i+len(frag) <= len(dsn); i++ {
		if dsn[i:i+len(frag)] == frag {
			return true
		}
	}
	return false
}

// ModuleSeedInstallerConfig — принятый защищённый вход установки.
// Присутствующий tenantAccountId выбирает S1 (пустое значение недопустимо); отсутствие выбирает S2.
// Для этого указателя не регистрируется умолчание: наличие принадлежит пользовательскому входу.
type ModuleSeedInstallerConfig struct {
	CredentialFile  string  `mapstructure:"credentialFile"`
	TenantAccountID *string `mapstructure:"tenantAccountId"`
}
