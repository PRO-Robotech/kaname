// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// registry_token.go — config for the Docker Registry v2 `/iam/token`
// auth-server HTTP listener (the `/iam/token` endpoint only). There is NO
// key-set endpoint on this listener: ключи проверки плоскости данных отдаёт
// ОТДЕЛЬНЫЙ внутренний публикатор (jwks_proxy.go /
// internal/handler/jwksproxyhttp), и запись у него одна — наша (зеркало набора
// провайдера снято, kaname#361).
//
// Здесь стояло, что токен выпускает внешний провайдер, а служба не чеканит
// ничего, — и противоречило соседнему абзацу про «the minted identity-JWT».
// Верно второе, и без оговорок: докерный токен чеканит НАШ подписант
// (`internal/registrytokenwire`, LocalMintAdapter поверх tokensigner); полоса
// без своей чеканки не собирается вовсе (kaname#494).
//
// The listener is EXTERNAL-reachable (docker clients hit `/iam/token` through
// the edge); TLS is terminated at the ingress, so the process binds plaintext —
// same posture as the hooks / metrics listeners. Policy fields (issuer, service,
// TTL) shape the minted identity-JWT and must match the data-plane's advertised
// Bearer realm.
package config

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"go.uber.org/multierr"

	"github.com/PRO-Robotech/kaname/internal/audiencepolicy"
	"github.com/PRO-Robotech/kaname/pkg/generatedid"
)

// Built-in policy defaults. viper also registers them (defaults.go); the
// accessors carry the same fallbacks so an unset struct (tests / partial config)
// still resolves to a valid policy.
//
// АДРЕСАТА (`service`) СРЕДИ НИХ НЕТ, И ЭТО РЕШЕНИЕ, А НЕ ПРОПУСК (задача kacho#1184).
// Имя службы реестра — тенант-фейсинг DNS, оно СВОЁ у каждого кластера, и у
// докерной полосы это имя общее с реестром: он называет его докер-клиенту, мы
// чеканим его в `aud`. Встроенное умолчание здесь было ВТОРЫМ объявлением того
// же предмета, живущим в другом дереве, — и оно молча расходилось с тем, что
// объявляет посадка реестра. Умолчания у величины, которую нельзя выбрать за
// оператора, быть не может: незаданный адресат отвергается стражем старта.
//
// ИЗДАТЕЛЯ (`issuer`) СРЕДИ НИХ НЕТ ПО ТОЙ ЖЕ ПРИЧИНЕ (kaname#309). Издатель —
// `iss` и область вызова на аутентификацию, то есть адрес НАШЕЙ полосы, а адрес
// у каждой установки свой. Здесь стояло умолчание, называвшее координату
// соседнего продукта: оно было непусто, поэтому страж старта по этой величине
// не исполнялся ни разу, и самостоятельная установка поднималась зелёной,
// чеканила удостоверения с чужим издателем и объявляла клиенту область по
// адресу, которого у неё нет. Незаданный издатель при поднятом слушателе
// отвергается стражем старта (Validate).
const defaultRegistryTokenTTL = 5 * time.Minute

// RegistryTokenConfig — api-server.registry-token section.
//
//	Endpoint — HTTP listen address (`tcp://0.0.0.0:9096` or bare `9096`).
//	           Empty disables the listener.
//	Issuer   — the `iss` claim + the WWW-Authenticate realm URL.
//	Service  — the default registry service name (→ `aud` + challenge service).
//	TTL      — minted-token lifetime (clamped to registry_token.MaxTTL downstream).
type RegistryTokenConfig struct {
	Endpoint string        `mapstructure:"endpoint"`
	Issuer   string        `mapstructure:"issuer"`
	Service  string        `mapstructure:"service"`
	TTL      time.Duration `mapstructure:"ttl"`

	// KeyMaterialWindowUntilRaw — ОКНО ПЕРЕХОДА ЛОМАЮЩЕГО ИЗМЕНЕНИЯ kacho#1143:
	// мгновение (RFC 3339), до которого докерная полоса ПРОДОЛЖАЕТ принимать
	// ключевой материал в поле пароля наряду с базовым токеном доступа.
	//
	// ENV: KANAME_API_SERVER__REGISTRY_TOKEN__KEY_MATERIAL_WINDOW_UNTIL
	// Пример значения: 2026-09-30T00:00:00Z
	//
	// УМОЛЧАНИЕ — ПУСТО, ТО ЕСТЬ ОКНО ЗАКРЫТО. Незаданное послабление не
	// означает «принимать оба»: fail-closed.
	//
	// ПРЕДИКАТ СНЯТИЯ ЭТОЙ РУЧКИ вписан в неё саму и состоит из двух частей:
	//   (1) она принимает МГНОВЕНИЕ, а не флажок, поэтому бессрочное окно ею
	//       невыразимо by construction и закрывается временем, а не памятью;
	//   (2) счётчик `kaname_registry_token_credential_kind_total` с меткой
	//       outcome="key_material_accepted_in_window" держит ноль при ненулевой
	//       сумме прочих исходов — значит прежним видом больше не входит никто,
	//       и ручку вместе с восстановленным ради неё проверяющим
	//       (registry_token/sakey_validator.go) снимают одним изменением.
	//
	// Цена обоих умолчаний измерена и названа в
	// registry_token/key_material_window.go — здесь она не пересказывается,
	// чтобы два места об одном предмете не разошлись.
	KeyMaterialWindowUntilRaw string `mapstructure:"key-material-window-until"`

	// AnonymousClientID — ПУБЛИЧНЫЙ ПРИНЦИПАЛ АНОНИМНОГО ЧТЕНИЯ (kaname#495):
	// субъект токена, который наш подписант выпускает на вход без
	// удостоверения (`docker pull` публичного репозитория без входа). Приёмная
	// сторона реестра резолвит этот субъект в системный класс `anonymous`, у
	// которого есть только чтение публикованных репозиториев.
	//
	// ENV: KANAME_API_SERVER__REGISTRY_TOKEN__ANONYMOUS_CLIENT_ID
	// Пример значения: registry-anonymous
	//
	// УМОЛЧАНИЕ — ПУСТО, ТО ЕСТЬ АНОНИМНЫЙ ПОТОК ВЫКЛЮЧЕН: вход без
	// удостоверения получает 401-вызов. Умолчания, которое тихо открывало бы
	// выдачу, нет: включает поток только оператор, объявив принципала, и то же
	// имя он объявляет приёмной стороне реестра.
	//
	// Форма значения закрыта (AnonymousPrincipalForm), и иная отвергается
	// стражем старта — разбор формы и цена её нарушения в AnonymousPrincipal.
	AnonymousClientID string `mapstructure:"anonymous-client-id"`

	// AnonymousPerSourcePerSec — темп анонимной выдачи: входов без
	// удостоверения в секунду на источник, НА ПРОЦЕСС (kaname#928). Источник —
	// по правилу адреса поверхности выдачи (Р7); запас — одна секунда темпа;
	// превышение — 429 со сроком ожидания. Несколько реплик дают источнику до
	// «темп × число реплик».
	//
	// ENV: KANAME_API_SERVER__REGISTRY_TOKEN__ANONYMOUS_PER_SOURCE_PER_SEC
	// Пример значения: 20
	//
	// Умолчания нет: при объявленном AnonymousClientID и поднятом слушателе
	// нулевой темп отвергается стражем старта (Validate). Ноль означал бы
	// «без ограничения» — выдачу, ни разу не отказавшую по частоте.
	AnonymousPerSourcePerSec int `mapstructure:"anonymous-per-source-per-sec"`

	// AnonymousForwarderSAN — ДОВЕРЕННЫЙ ПЕРЕСЫЛЬЩИК точки анонимной выдачи
	// (kaname#930): ТОЧНЫЙ идентификатор (URI SAN) клиентского сертификата
	// прокси реестра, через который к службе приходит анонимный вход.
	//
	// ENV: KANAME_API_SERVER__REGISTRY_TOKEN__ANONYMOUS_FORWARDER_SAN
	// Пример значения: spiffe://kacho.cloud/ns/kacho/sa/kacho-registry
	//
	// От пира с ПРОВЕРЕННЫМ сертификатом этого идентификатора ключ темпа на
	// источник — адрес клиента из одного значения `X-Forwarded-For` (правило
	// `internal/issuingsource`); от любого другого пира заголовок не читается.
	// Форма — та же, что у кругов отправителей соседних ручек
	// (`authn.trusted-forwarder-sans`): точный SPIFFE-идентификатор рабочей
	// нагрузки нашего домена доверия, а не имя службы.
	//
	// Умолчания нет: при объявленном AnonymousClientID и поднятом слушателе
	// незаданный пересыльщик отвергается стражем старта (Validate). Без него
	// ключом темпа был бы адрес самого прокси, и предел стал бы общим на всех
	// клиентов за ним. Слушатель при анонимном потоке обязан запрашивать
	// клиентский сертификат — это судит страж корня
	// requireIssuingListenerAsksForACertificate.
	AnonymousForwarderSAN string `mapstructure:"anonymous-forwarder-san"`
}

// anonymousForwarderLabelRe — сегмент пространства имён и учётной записи в
// идентификаторе пересыльщика: метка имени в кластере.
var anonymousForwarderLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// AnonymousLaneDeclared — анонимный поток поднят: принципал объявлен и
// слушатель полосы есть. Один предикат на стража настройки и стража корня.
func (c RegistryTokenConfig) AnonymousLaneDeclared() bool {
	return c.AnonymousClientID != "" && c.ListenAddress() != ""
}

// AnonymousForwarder — объявленный доверенный пересыльщик точки анонимной
// выдачи в домене доверия trust.
//
// Пустое + nil — пересыльщик не объявлен. Ошибка — значение написано, но не
// формы `spiffe://<домен>/ns/<пространство>/sa/<учётная запись>` нашего домена:
// такое значение не совпало бы ни с одним предъявленным сертификатом
// (сравнение точное), и поток поднялся бы с общим на всех темпом молча.
// Обрезки пробелов нет по той же причине, что у принципала: обрезанное
// значение было бы не тем, что объявил оператор.
func (c RegistryTokenConfig) AnonymousForwarder(trust grpcsrv.TrustDomain) (string, error) {
	v := c.AnonymousForwarderSAN
	if v == "" {
		return "", nil
	}
	if !trust.IsDeclared() {
		return "", fmt.Errorf(
			"api-server.registry-token.anonymous-forwarder-san %q is declared while authn.trust-domain is not — "+
				"an undeclared trust domain recognises no certificate, so the forwarder would never be recognised "+
				"and every anonymous client behind it would share one pace. Declare authn.trust-domain "+
				"(env KANAME_AUTHN__TRUST_DOMAIN)", v)
	}
	if !forwarderSANWellFormed(trust, v) {
		return "", fmt.Errorf(
			"api-server.registry-token.anonymous-forwarder-san %q is not of the declared form "+
				"%s<namespace>/sa/<service account> (lower-case labels, nothing after the account) — it is "+
				"compared EXACTLY with the identity of the verified client certificate, and a value of another "+
				"form would never match, leaving every anonymous client behind the registry proxy on one pace. "+
				"Example: %skacho/sa/kacho-registry. Env KANAME_API_SERVER__REGISTRY_TOKEN__ANONYMOUS_FORWARDER_SAN",
			v, trust.NamespacePrefix(), trust.NamespacePrefix())
	}
	return v, nil
}

// forwarderSANWellFormed — v есть `<префикс пространств домена><ns>/sa/<sa>`, оба
// сегмента — метки имени в кластере.
func forwarderSANWellFormed(trust grpcsrv.TrustDomain, v string) bool {
	rest, ok := strings.CutPrefix(v, trust.NamespacePrefix())
	if !ok {
		return false
	}
	ns, sa, ok := strings.Cut(rest, "/sa/")
	return ok && anonymousForwarderLabelRe.MatchString(ns) && anonymousForwarderLabelRe.MatchString(sa)
}

// AnonymousPrincipalForm — объявленная форма публичного принципала анонимного
// чтения: слова из строчных латинских букв и цифр через дефис, не меньше двух
// слов, длина до 63 знаков.
const AnonymousPrincipalForm = `^[a-z][a-z0-9]*(-[a-z0-9]+)+$`

const anonymousPrincipalMaxLen = 63

// anonymousPrincipalRe — объявленная форма публичного принципала. Форма
// порождённого идентификатора, которой принципал иметь не вправе, — не здесь:
// её определение одно, в публичном пакете `pkg/generatedid`. Приёмная сторона
// реестра обязана судить форму субъекта этим же определением, а не своей
// копией выражения (kaname#908).
var anonymousPrincipalRe = regexp.MustCompile(AnonymousPrincipalForm)

// AnonymousPrincipal — объявленный публичный принципал анонимного чтения.
//
// Пустое + nil — анонимный поток выключен (умолчание). Ошибка — значение
// написано, но не объявленной формы, и тогда исход ОДИН — отказ в старте:
//
//   - субъект, совпадающий по форме с порождённым идентификатором (служебная
//     учётка `sva…`, человек `usr…`), превратил бы анонимный токен в токен
//     настоящего принципала — то есть выдал бы его права всякому без
//     удостоверения. Двухсловное имя через дефис с такими идентификаторами не
//     совпадает по построению, а форма порождённого отвергается сверх того —
//     на случай вида, чей префикс пишется через дефис;
//   - пробел по краю, верхний регистр, говорящий модели прав
//     (`system_class:anonymous`) и подстановка (`user:*`) — значения, которые
//     приёмная сторона прочтёт иначе, чем выпущено, либо не той сущностью;
//     догадка в любую сторону даёт посадку, которой оператор не выбирал.
//
// Обрезки пробелов здесь нет намеренно: обрезанное значение ушло бы в токен
// не тем, что объявлено приёмной стороне.
func (c RegistryTokenConfig) AnonymousPrincipal() (string, error) {
	v := c.AnonymousClientID
	if v == "" {
		return "", nil
	}
	if len(v) > anonymousPrincipalMaxLen || !anonymousPrincipalRe.MatchString(v) ||
		generatedid.Matches(v) {
		return "", fmt.Errorf(
			"api-server.registry-token.anonymous-client-id %q is not of the declared form %s "+
				"(at most %d characters, and never shaped like a generated identifier) — it is the "+
				"subject of the read-only token minted for a caller WITHOUT credentials, and a value "+
				"that can coincide with a real principal would hand that principal's access to anyone. "+
				"Example: registry-anonymous. Unset (env KANAME_API_SERVER__REGISTRY_TOKEN__ANONYMOUS_CLIENT_ID "+
				"empty) keeps anonymous pull OFF",
			v, AnonymousPrincipalForm, anonymousPrincipalMaxLen)
	}
	return v, nil
}

// KeyMaterialWindowUntil — разобранное мгновение окна перехода.
//
// Нулевое время + nil — окно не объявлено (умолчание). Ошибка — значение
// написано, но неразборчиво; тогда исход ОДИН — отказ, потому что догадка в
// любую сторону даёт посадку, которой оператор не выбирал: «принимать оба»
// открыло бы приём снятого вида опечаткой, а молчаливое закрытие оставило бы
// оператора в уверенности, что окно есть, — и сломало бы ровно тех
// арендаторов, которых он берёг.
func (c RegistryTokenConfig) KeyMaterialWindowUntil() (time.Time, error) {
	raw := strings.TrimSpace(c.KeyMaterialWindowUntilRaw)
	if raw == "" {
		return time.Time{}, nil
	}
	until, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf(
			"api-server.registry-token.key-material-window-until %q is not an RFC 3339 instant "+
				"(example: 2026-09-30T00:00:00Z) — this knob is the TRANSITION WINDOW of a breaking "+
				"change: while it is open the docker lane keeps accepting key material in the password "+
				"field alongside the Kacho basic access token. It takes an INSTANT and not a flag on "+
				"purpose: an unbounded window never expires, so it would silently keep private key "+
				"halves travelling over the wire forever. Unset means the window is CLOSED",
			c.KeyMaterialWindowUntilRaw)
	}
	return until, nil
}

// ListenAddress — normalised listen-addr for the token HTTP server (empty
// endpoint → empty, i.e. the listener is disabled). Separate external port from
// the gRPC / hooks / metrics listeners.
func (c RegistryTokenConfig) ListenAddress() string { return listenAddress(c.Endpoint) }

// TokenIssuer — объявленный издатель полосы: `iss` выпускаемого токена и
// область (`realm`) вызова на аутентификацию. ВСТРОЕННОЙ ПОДМЕНЫ НЕТ (kaname#309):
// незаданное возвращается пустым, и полоса с пустым издателем до старта не
// доживает (см. Validate) — так же, как с пустым адресатом рядом.
func (c RegistryTokenConfig) TokenIssuer() string {
	return strings.TrimSpace(c.Issuer)
}

// TokenService — объявленное имя службы реестра (`aud` + `service=` в вызове на
// аутентификацию). ВСТРОЕННОЙ ПОДМЕНЫ НЕТ: незаданное возвращается пустым, и
// полоса с пустым адресатом до старта не доживает (см. Validate). Подставлять
// здесь «какое-нибудь» имя значило бы выбирать за оператора величину, которая у
// каждого кластера своя, и делать это молча.
func (c RegistryTokenConfig) TokenService() string {
	return strings.TrimSpace(c.Service)
}

// TokenTTL — the minted-token lifetime. Non-positive values fall back to the
// built-in default (the use-case additionally clamps to registry_token.MaxTTL).
func (c RegistryTokenConfig) TokenTTL() time.Duration {
	if c.TTL <= 0 {
		return defaultRegistryTokenTTL
	}
	return c.TTL
}

// Validate — страж старта докерной полосы выдачи (задача kacho#1184).
//
// # Что здесь проверяется и почему именно здесь
//
// Полос выдачи по ключу служебной учётки ДВЕ, и обе чеканят удостоверения от
// имени одной платформы. Перечень адресатов платформы объявляет посадка
// (`authn.client-token.allowed-audiences`); адресат докерной полосы объявляет
// `api-server.registry-token.service`. Пока эти две величины не сверены, наш
// подписант вправе выпустить удостоверение, адресованное поверхности, которую
// посадка не объявляла, — и не проявится это ничем: запрос проходит, токен
// выдаётся, докер-клиент доволен.
//
// Сверка живёт на СТАРТЕ, а не на выдаче: перечень платформы — величина
// оператора, и расхождение двух его объявлений есть настройка, а не запрос.
// Отказ здесь виден оператору сразу и называет обе настройки; отказ на выдаче
// виден клиенту и выглядит неисправностью реестра.
//
// Принимает настройку токен-эндпоинта ПАРАМЕТРОМ, а не читает её из корня: две
// величины связаны по существу, и связь обязана проверяться там, где она есть,
// а не там, где о ней помнят.
func (c RegistryTokenConfig) Validate(clientToken ClientTokenConfig, trust grpcsrv.TrustDomain) error {
	// Окно перехода kacho#1143 разбирается СТРАЖЕМ СТАРТА, а не только на пути
	// запроса. Разобранное лишь на пути запроса означает, что процесс поднялся
	// с настройкой, которой нет, и узнает об этом первый вошедший клиент.
	//
	// Проверяется ДО прочих сверок и НЕЗАВИСИМО от того, поднят ли слушатель:
	// написанная и неразборчивая ручка есть ошибка настройки при любом составе
	// полос, а страж, молчащий о ней при выключенном слушателе, оставил бы
	// опечатку доживать до включения.
	if _, err := c.KeyMaterialWindowUntil(); err != nil {
		return err
	}
	// Публичный принципал анонимного чтения — по той же причине и тем же
	// порядком: написанное значение не той формы есть ошибка настройки при
	// любом составе полос (kaname#495).
	if _, err := c.AnonymousPrincipal(); err != nil {
		return err
	}
	// Доверенный пересыльщик (kaname#930) — тем же порядком: написанное
	// значение не той формы не совпадёт ни с одним сертификатом при любом
	// составе полос.
	if _, err := c.AnonymousForwarder(trust); err != nil {
		return err
	}
	if c.ListenAddress() == "" {
		// Слушателя нет — полосы нет, и сверять нечего. Страж, требующий того,
		// чем не пользуются, есть отказ в старте без предмета.
		return nil
	}
	// НЕСВЯЗАННОСТЬ СТОРОН. Полоса поднята, а её адресат не объявлен ничем:
	// сторона реестра приезжает из посадки, наша — ниоткуда. Прежде дыру
	// затыкало встроенное умолчание, и результат зависел от того, совпало ли
	// оно с именем, которое реестр называет докер-клиенту; совпадения не
	// выбирал никто. Отказ называет ОБЕ величины: свою настройку и ту сторону,
	// из которой она выводится, — иначе оператор ищет вслепую.
	// ТЕМП АНОНИМНОЙ ВЫДАЧИ (kaname#928): поток объявлен — темп на источник
	// объявлен числом. Без анонимного потока величина не требуется.
	if c.AnonymousLaneDeclared() && c.AnonymousPerSourcePerSec <= 0 {
		return fmt.Errorf(
			"api-server.registry-token.anonymous-per-source-per-sec must be declared as a positive number "+
				"of anonymous registry token requests per second per source, per replica, while "+
				"api-server.registry-token.anonymous-client-id is set (got %d) — zero means «no pace». "+
				"Env KANAME_API_SERVER__REGISTRY_TOKEN__ANONYMOUS_PER_SOURCE_PER_SEC",
			c.AnonymousPerSourcePerSec)
	}
	// ДОВЕРЕННЫЙ ПЕРЕСЫЛЬЩИК (kaname#930): анонимный вход приходит через прокси
	// реестра, и без пересыльщика ключом темпа на источник был бы адрес самого
	// прокси — предел, общий на всех клиентов за ним.
	if c.AnonymousLaneDeclared() && c.AnonymousForwarderSAN == "" {
		return fmt.Errorf(
			"api-server.registry-token.anonymous-forwarder-san must be declared while "+
				"api-server.registry-token.anonymous-client-id is set — anonymous registry token requests reach "+
				"this service through the registry proxy, and without a trusted forwarder the pace key is the "+
				"proxy's own address, one pace shared by every client behind it. Declare the exact identity of "+
				"the proxy's client certificate in the form %s<namespace>/sa/<service account>. "+
				"Env KANAME_API_SERVER__REGISTRY_TOKEN__ANONYMOUS_FORWARDER_SAN", trust.NamespacePrefix())
	}
	// Адресат и издатель — две несвязанности ОДНОГО рода, и судятся они вместе:
	// отказ, называющий одну из двух, отправил бы оператора на второй
	// перезапуск ради второй ручки.
	var undeclared error
	if c.TokenService() == "" {
		undeclared = multierr.Append(undeclared, fmt.Errorf(
			"api-server.registry-token.service is not declared while the docker lane listener is up (%s) — "+
				"this addressee is not ours to default: it is the registry's own service name, declared once "+
				"by the deployment as global.kacho.registry.serviceAud and read by BOTH sides of the lane "+
				"(the registry ships it as KACHO_REGISTRY_SERVICE_AUD and advertises it to the docker client; "+
				"we mint it into aud). Declare global.kacho.registry.serviceAud, or set this key directly "+
				"when running iam on its own (env KANAME_API_SERVER__REGISTRY_TOKEN__SERVICE)",
			c.ListenAddress()))
	}
	// ИЗДАТЕЛЬ (kaname#309) — та же несвязанность, что у адресата выше: полоса
	// поднята, а адрес, который она называет клиенту и вписывает в каждое
	// удостоверение, не объявлен ничем. Потребитель выбирает запись набора
	// ключей по объявленному издателю, отката между записями нет — подставленный
	// издатель отказал бы во входе каждому докерному клиенту, не назвав ручки.
	if c.TokenIssuer() == "" {
		undeclared = multierr.Append(undeclared, fmt.Errorf(
			"api-server.registry-token.issuer is not declared while the docker lane listener is up (%s) — "+
				"it is the iss claim of every minted token and the realm the docker client is sent to, that is, "+
				"the address of THIS installation's token endpoint, and there is no address to default it to. "+
				"Declare it as the public URL of the token endpoint (example https://iam.example.invalid/iam/token; "+
				"env KANAME_API_SERVER__REGISTRY_TOKEN__ISSUER), the same value the registry advertises as its token realm",
			c.ListenAddress()))
	}
	if undeclared != nil {
		return undeclared
	}
	if !clientToken.Enabled {
		// Перечень платформы не объявлен вовсе. Внешняя граница этой полосы при
		// этом остаётся — ею служит собственный объявленный адресат, — поэтому
		// сверять здесь не с чем, и отказывать не за что.
		return nil
	}
	landing := clientToken.AudienceList()
	if len(landing) == 0 {
		// Пустой перечень при включённом эндпоинте — предмет стража токен-
		// эндпоинта, и он о нём уже сказал. Второе сообщение о том же предмете
		// разошлось бы с первым.
		return nil
	}
	if !audiencepolicy.Contains(landing, c.TokenService()) {
		return fmt.Errorf(
			"api-server.registry-token.service %q is outside authn.client-token.allowed-audiences %q — "+
				"the docker lane would mint a credential addressed to a surface this deployment never "+
				"declared, and the platform's own token endpoint would refuse that same audience",
			c.TokenService(), clientToken.AllowedAudiences)
	}
	return nil
}
