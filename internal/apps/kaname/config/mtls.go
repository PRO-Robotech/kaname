// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"go.uber.org/multierr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	corecfg "github.com/PRO-Robotech/kacho/pkg/config"
	"github.com/PRO-Robotech/kacho/pkg/grpcclient"
	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

// EnvPrefix — корневой сегмент ВСЕХ env-имен службы, объявленный ОДИН раз.
//
// Прежде он стоял двумя литералами: здесь и в load.go (`SetEnvPrefix`). Два
// места об одном предмете расходятся молча, и расхождение здесь особенно тихое —
// часть ручек продолжала бы читаться под прежним именем, а часть нет, и оператор
// увидел бы это только по последствиям. Переименование службы в Kaname (#2076)
// было бы ровно таким случаем.
//
// LoadPrefixed (envconfig) выводит env-имя каждого поля из иерархии:
// EnvPrefix + tag родительского поля + field примитива → KANAME_<EDGE>_<NAME>.
const EnvPrefix = "KANAME"

// mtlsEnvPrefix — тот же префикс под прежним внутренним именем: у per-edge mTLS
// своего словаря имён нет.
const mtlsEnvPrefix = EnvPrefix

// MTLSConfig — per-edge opt-in server-side mTLS для listener'ов IAM (+
// HTTP-listener hardening). Загружается ОТДЕЛЬНО от основного
// viper-конфига через envconfig (LoadMTLS) — grpcsrv.TLSServer это
// горизонтальная corelib value-структура без mapstructure-тегов; envconfig
// обрабатывает ее поля напрямую.
//
// IAM — leaf-owner ресурсной модели (vpc/compute/nlb дилят IAM как клиенты, сам
// IAM исходящих peer-дилов на ресурсы не делает), поэтому здесь только
// server-edges. subject_change-drainer → api-gateway internal — отдельный
// client-edge, конфигурируется в composition root (cmd/kaname/
// снятым дренажом смены субъекта) и вне scope.
//
// Каждое ребро независимо: env-имена выводятся из тега родительского поля.
// Напр. InternalServerMTLS → KANAME_INTERNAL_SERVER_MTLS_{ENABLE,CERTFILE,
// KEYFILE,CLIENTCAFILES}. Enable=false (default) → insecure/plaintext (dev
// backward-compat). Per-edge enable → независимый rollback.
//
// Server-edge'и:
//   - PublicServerMTLS   — gRPC public listener (:9090), grpc.ServerOption.
//   - InternalServerMTLS — gRPC internal listener (:9091), grpc.ServerOption.
//   - HooksServerMTLS    — HTTP Hydra/Kratos hooks listener (:9092), *tls.Config.
//   - MetricsServerMTLS  — HTTP Prometheus /metrics listener (:9095), *tls.Config.
//   - JWKSProxyServerMTLS     — HTTP Hydra-JWKS proxy (:9097), *tls.Config.
//   - RegistryTokenServerMTLS — HTTP docker-token shim (:9096), *tls.Config.
//
// gRPC-ребра отдают grpc.ServerOption (передается в grpcsrv.NewServer);
// HTTP-ребра отдают *tls.Config, который composition root ОБЪЯВЛЯЕТ полем
// профиля не-gRPC поверхности (`servicecontract.Surface.TLS`), а надевает на
// слушатель сам профиль (`servicehost.ServeSurface`). Прежде обёртку писал
// корень; после XC-7/Ф8 это решение стало объявлением и попадает в самоотчёт при
// старте. Default-off у HTTP-ребер → builder возвращает (nil, nil) → слушатель
// остаётся PLAINTEXT.
type MTLSConfig struct {
	// PublicServerMTLS — server-creds для публичного listener (:9090,
	// tenant-facing RPC через api-gateway).
	PublicServerMTLS grpcsrv.TLSServer `envconfig:"PUBLIC_SERVER_MTLS"`

	// InternalServerMTLS — server-creds для cluster-internal listener (:9091,
	// InternalIAMService/InternalUserService). mTLS делает уже-существующие
	// UnaryCertIdentityExtract/StreamCertIdentityExtract функциональными:
	// извлекатель видит верифицированный peer-cert SAN (на plaintext — no-op).
	InternalServerMTLS grpcsrv.TLSServer `envconfig:"INTERNAL_SERVER_MTLS"`

	// HooksServerMTLS — server-creds для HTTP Hydra/Kratos hooks listener
	// (:9092). Listener несет ТРИ HMAC-аутентифицируемых hook-эндпоинта
	// (Hydra token/refresh + Kratos provision) — все три вызывателя — HTTP-клиенты
	// без transport client-cert. HMAC shared-secret в handler'е (общий
	// requireHookAuth) дает fail-closed caller-auth; TLS добавляет шифрование +
	// server-authentication. ClientAuth-режим — per-edge HooksClientAuthMode:
	// server-tls-only (default) → tls.NoClientCert (client-cert
	// не требуется, потому что Ory его не умеет); mutual → RequireAndVerifyClientCert.
	// Default-off (Enable=false) → plaintext (dev/newman стенд).
	HooksServerMTLS grpcsrv.TLSServer `envconfig:"HOOKS_SERVER_MTLS"`

	// HooksServerPlaintextAcknowledged — ОБЪЯВЛЕННОЕ ИСКЛЮЧЕНИЕ: слушатель
	// обратных вызовов работает открытым текстом СОЗНАТЕЛЬНО.
	// Env: KANAME_HOOKS_SERVER_PLAINTEXT_ACKNOWLEDGED.
	//
	// Страж старта в боевой посадке не пускает ни одно HTTP-ребро открытым
	// текстом. У этого ребра исключение возможно, и основание у него измерено, а
	// не выведено: вызывающий — вебхук службы личности — ходит по открытому http
	// и своего доверия не несёт, поэтому TLS здесь означал бы не защиту, а
	// проваленный хук и неработающую выдачу токенов целиком.
	//
	// ПОЛЕ ОДНО НА ВСЮ ПОСАДКУ, И ЭТО ОБЛАСТЬ ИСКЛЮЧЕНИЯ, А НЕ НЕДОДЕЛКА. У
	// остальных HTTP-рёбер такого поля НЕТ, поэтому объявить им открытый текст
	// нечем: сужение держится построением, а не дисциплиной оператора. Заводя
	// такое поле следующему ребру, спроси, чем измерено его основание.
	//
	// Объявить исключение ВМЕСТЕ с транспортом — отказ старта: два правила об
	// одном предмете говорят противоположное, и выбирать между ними молча
	// процесс не вправе.
	HooksServerPlaintextAcknowledged bool `envconfig:"HOOKS_SERVER_PLAINTEXT_ACKNOWLEDGED"`

	// HooksClientAuthMode — per-edge TLS ClientAuth-режим для hooks-listener'а
	// (:9092). Env: KANAME_HOOKS_SERVER_MTLS_CLIENTAUTHMODE. Допустимые
	// значения — clientAuthServerTLSOnly | clientAuthMutual. Пустая строка
	// (unset) при enabled-edge → безопасный per-edge дефолт server-tls-only (Ory
	// не предъявляет client-cert; иначе enabled hooks-edge падал бы в
	// RequireAndVerifyClientCert). Неизвестный режим → fail-closed
	// (НИКОГДА не интерпретируется как «без проверок»).
	HooksClientAuthMode string `envconfig:"HOOKS_SERVER_MTLS_CLIENTAUTHMODE"`

	// MetricsServerMTLS — server-creds для HTTP Prometheus /metrics listener
	// (:9095). Cluster-internal, never tenant-facing. mTLS закрывает plaintext
	// metrics-поверхность. ClientAuth-режим — per-edge MetricsClientAuthMode:
	// server-tls-only (default — в деплое нет scrape-клиента с client-cert);
	// mutual → RequireAndVerifyClientCert (опция на момент, когда scrape-клиент
	// будет provision'ен с internal-CA client-cert). Default-off → plaintext.
	MetricsServerMTLS grpcsrv.TLSServer `envconfig:"METRICS_SERVER_MTLS"`

	// MetricsClientAuthMode — per-edge TLS ClientAuth-режим для metrics-listener'а
	// (:9095). Env: KANAME_METRICS_SERVER_MTLS_CLIENTAUTHMODE. Пустая строка
	// (unset) при enabled-edge → безопасный per-edge дефолт server-tls-only.
	// Неизвестный режим → fail-closed.
	MetricsClientAuthMode string `envconfig:"METRICS_SERVER_MTLS_CLIENTAUTHMODE"`

	// JWKSProxyServerMTLS — server-creds для HTTP Hydra-JWKS proxy listener
	// (:9097, cluster-internal `GET /.well-known/jwks.json`). Data-plane
	// verification keys (public OIDC material), served internal-only over
	// ONE-WAY server-TLS (internal-CA leaf; NOT mutual — see JWKSProxyClientAuthMode
	// default server-tls-only). The route is unauthenticated-by-design (public keys,
	// standard OIDC well-known) — a conscious, documented exception to the
	// authN-on-every-listener invariant (security.md), justified by internal-only
	// surface + server-TLS + only-public-material. Default-off (Enable=false) →
	// plaintext (dev/newman стенд byte-identical). Env:
	// KANAME_JWKSPROXY_SERVER_MTLS_{ENABLE,CERTFILE,KEYFILE,CLIENTCAFILES}.
	JWKSProxyServerMTLS grpcsrv.TLSServer `envconfig:"JWKSPROXY_SERVER_MTLS"`

	// JWKSProxyClientAuthMode — per-edge TLS ClientAuth-режим для jwks-proxy
	// listener'а (:9097). Env: KANAME_JWKSPROXY_SERVER_MTLS_CLIENTAUTHMODE.
	// Пустая строка (unset) при enabled-edge → безопасный per-edge дефолт
	// server-tls-only (ONE-WAY: registry-verifier предъявляет только server-trust,
	// не client-cert — mutual сломал бы «verifier untouched»). Неизвестный режим →
	// fail-closed.
	JWKSProxyClientAuthMode string `envconfig:"JWKSPROXY_SERVER_MTLS_CLIENTAUTHMODE"`

	// RESTUpstreamMTLS — удостоверение, которым REST-фронт представляется
	// СОБСТВЕННОМУ gRPC-слушателю.
	//
	// Фронт — обычный клиент своего слушателя, и широкого допуска он не
	// получает: в круг разрешённых отправителей личности он не вносится, и
	// «этому клиенту можно всё» ему не выдаётся. Единственное, чем запрос,
	// пришедший через фронт, называет субъекта, — предъявленное арендатором
	// удостоверение, которое фронт переносит, ничего к нему не добавляя.
	//
	// Ручка ОДНА на оба фронта: это один процесс, и личность у него одна.
	// Вторая ручка об одном предмете разошлась бы с первой молча.
	// Env: KANAME_REST_UPSTREAM_MTLS_{ENABLE,CERTFILE,KEYFILE,CAFILES,SERVERNAME}.
	RESTUpstreamMTLS grpcclient.TLSClient `envconfig:"REST_UPSTREAM_MTLS"`

	// RESTServerMTLS — server-creds ПУБЛИЧНОГО REST-фронта службы. Env:
	// KANAME_REST_SERVER_MTLS_{ENABLE,CERTFILE,KEYFILE,CLIENTCAFILES}.
	RESTServerMTLS grpcsrv.TLSServer `envconfig:"REST_SERVER_MTLS"`

	// RESTClientAuthMode — per-edge TLS ClientAuth-режим публичного фронта.
	// Env: KANAME_REST_SERVER_MTLS_CLIENTAUTHMODE.
	RESTClientAuthMode string `envconfig:"REST_SERVER_MTLS_CLIENTAUTHMODE"`

	// InternalRESTServerMTLS — server-creds ВНУТРЕННЕГО REST-фронта. Env:
	// KANAME_INTERNALREST_SERVER_MTLS_{ENABLE,CERTFILE,KEYFILE,CLIENTCAFILES}.
	InternalRESTServerMTLS grpcsrv.TLSServer `envconfig:"INTERNALREST_SERVER_MTLS"`

	// InternalRESTClientAuthMode — per-edge TLS ClientAuth-режим внутреннего
	// фронта. Env: KANAME_INTERNALREST_SERVER_MTLS_CLIENTAUTHMODE.
	InternalRESTClientAuthMode string `envconfig:"INTERNALREST_SERVER_MTLS_CLIENTAUTHMODE"`

	// RegistryTokenServerMTLS — server-creds для HTTP docker-token listener
	// (:9096, `/iam/token`).
	//
	// ЧТО ПО НЕМУ ЕДЕТ: `docker login` предъявляет HTTP Basic, и пароль в этой паре
	// — ПРИВАТНЫЙ КЛЮЧ ключа служебной учётки. Сервер его не хранит вовсе (выводит
	// SPKI из предъявленного и сверяет с сохранённым публичным), поэтому этот хоп —
	// единственное место в системе, где приватный ключ транзитит; срок его жизни не
	// ограничен и ротации нет, так что снятый с провода credential предъявляется
	// напрямую, без окна TTL. Соседний jwks-proxy возит только ПУБЛИЧНЫЙ материал и
	// TLS получил раньше — эта нога осталась открытой при несимметричной починке
	// того же класса.
	//
	// Режим — server-tls-only (ONE-WAY): caller-auth на этом эндпоинте и ЕСТЬ Basic
	// (в этом его смысл), не хватало именно шифрования и аутентификации сервера;
	// mutual потребовал бы client-cert у nginx-sidecar реестра. Default-off →
	// (nil, nil) → plaintext (dev байт-идентичен); в production listener без TLS
	// отказывается стартовать (requireRegistryTokenTLS). Env:
	// KANAME_REGISTRYTOKEN_SERVER_MTLS_{ENABLE,CERTFILE,KEYFILE,CLIENTCAFILES}.
	RegistryTokenServerMTLS grpcsrv.TLSServer `envconfig:"REGISTRYTOKEN_SERVER_MTLS"`

	// RegistryTokenClientAuthMode — per-edge TLS ClientAuth-режим для docker-token
	// listener'а (:9096). Env:
	// KANAME_REGISTRYTOKEN_SERVER_MTLS_CLIENTAUTHMODE. Пустая строка (unset) при
	// enabled-ребре → server-tls-only. Неизвестный режим → fail-closed.
	RegistryTokenClientAuthMode string `envconfig:"REGISTRYTOKEN_SERVER_MTLS_CLIENTAUTHMODE"`
}

// clientAuthMode — TLS ClientAuth-режим per-edge для HTTP-listener'ов.
// Строго fail-closed: только два известных режима, неизвестная строка —
// ошибка (никогда не падает в небезопасный режим).
const (
	// clientAuthServerTLSOnly — server-side TLS без верификации client-cert
	// (tls.NoClientCert). Транспорт зашифрован + server-authentication; caller-auth
	// обеспечивается выше по стеку (HMAC X-Kacho-Hook-Token на hooks-ребре;
	// network-segregation на metrics-ребре). Client-CA НЕ требуется. Корректен
	// для Ory webhooks (Hydra token/refresh + Kratos provision), которые не умеют
	// предъявлять transport client-cert.
	clientAuthServerTLSOnly = "server-tls-only"

	// clientAuthMutual — mTLS с RequireAndVerifyClientCert (требует client-CA).
	// Прежнее жестко-зашитое поведение; теперь — явный opt-in per-edge.
	clientAuthMutual = "mutual"

	// clientAuthOptionalMutual — client-cert ЗАПРАШИВАЕТСЯ и, если предъявлен,
	// ВЕРИФИЦИРУЕТСЯ против client-CA (tls.VerifyClientCertIfGiven); не
	// предъявлен — соединение продолжается. Требует client-CA.
	//
	// Режим заведён ради ребра, на котором соседствуют две поверхности с
	// разными требованиями: набор проверочных ключей обязан оставаться
	// origin-agnostic (потребитель не предъявляет ничего и не должен), а
	// авторитет отзыва принимает предъявленный токен и потому обязан знать,
	// КТО спрашивает.
	//
	// Опасность режима названа прямо: сам по себе он НИЧЕГО не сужает —
	// соединение без сертификата проходит. Сужает обработчик, который требует
	// проверенного пира; поэтому обработчик, полагающийся на этот режим,
	// обязан отказывать при отсутствии сертификата САМ, а не считать, что за
	// него это сделал транспорт.
	clientAuthOptionalMutual = "optional-mutual"
)

// JWKSProxyVerifiesCaller отвечает, способен ли слушатель набора проверочных
// ключей УСТАНОВИТЬ, кто к нему пришёл.
//
// Вопрос нужен не набору ключей — ему личность спрашивающего не нужна и не
// должна быть нужна, — а СОСЕДНЕЙ поверхности того же слушателя: авторитету
// отзыва, которому присылают предъявленный токен. Он обязан знать, кто
// спрашивает, и потому не монтируется на слушателе, который сертификата даже
// не запрашивает: обработчик, не имеющий чем отказать, — контроль, который не
// откажет ни разу.
func (m MTLSConfig) JWKSProxyVerifiesCaller() bool {
	if !m.JWKSProxyServerMTLS.Enable {
		return false
	}
	switch resolveClientAuthMode(m.JWKSProxyClientAuthMode) {
	case clientAuthMutual, clientAuthOptionalMutual:
		return true
	default:
		return false
	}
}

// resolveClientAuthMode возвращает эффективный ClientAuth-режим для ребра:
// пустая строка → безопасный per-edge дефолт server-tls-only (явное осознанное
// решение, не случайный zero-value: ни Ory webhooks, ни metrics scrape-клиент
// не предъявляют client-cert). Известное значение возвращается как есть;
// неизвестное — как есть (валидируется/отвергается вызывающим builder/Validate).
func resolveClientAuthMode(mode string) string {
	if mode == "" {
		return clientAuthServerTLSOnly
	}
	return mode
}

// LoadMTLS читает per-edge server-side mTLS-конфиг из env (KANAME_*).
// enable=false по каждому ребру (zero-value) → текущее insecure/plaintext-
// поведение (dev, нулевая регрессия).
func LoadMTLS() (MTLSConfig, error) {
	var m MTLSConfig
	if err := corecfg.LoadPrefixed(mtlsEnvPrefix, &m); err != nil {
		return MTLSConfig{}, err
	}
	return m, nil
}

// PublicServerCreds возвращает grpc.ServerOption для публичного listener (:9090).
// Enable=false → insecure (dev backward-compat); enable=true без валидного
// cert-trio → error (fail-closed, без silent insecure-fallback).
func (m MTLSConfig) PublicServerCreds() (grpc.ServerOption, error) {
	return grpcsrv.TLSServerCreds(m.PublicServerMTLS)
}

// InternalServerCreds возвращает grpc.ServerOption для internal listener (:9091).
func (m MTLSConfig) InternalServerCreds() (grpc.ServerOption, error) {
	return grpcsrv.TLSServerCreds(m.InternalServerMTLS)
}

// HooksServerTLSConfig возвращает *tls.Config для HTTP hooks listener (:9092),
// который composition root объявляет полем TLS профиля поверхности.
//
// Контракт (per-edge ClientAuth mode):
//   - enable=false → (nil, nil): cert-файлы НЕ читаются, listener остается
//     PLAINTEXT (dev/newman стенд byte-identical к текущему поведению);
//   - enable=true, clientAuthMode=server-tls-only (default) → server-side TLS:
//     предъявляет server-cert (cert/key), ClientAuth=tls.NoClientCert; client-CA
//     НЕ требуется (Ory webhooks не умеют client-cert, caller-auth — HMAC);
//   - enable=true, clientAuthMode=mutual → mTLS: + верифицирует client-cert против
//     client-CA с ClientAuth=RequireAndVerifyClientCert;
//   - enable=true + нечитаемый/мусорный cert → error; mutual + пустой client-CA →
//     error; неизвестный clientAuthMode → error (fail-closed; никогда silent
//     plaintext fallback и никогда не интерпретировать unknown как «без проверок»,
//     ban #11).
func (m MTLSConfig) HooksServerTLSConfig() (*tls.Config, error) {
	return serverTLSConfig(m.HooksServerMTLS, resolveClientAuthMode(m.HooksClientAuthMode))
}

// MetricsServerTLSConfig возвращает *tls.Config для HTTP /metrics listener
// (:9095). Тот же контракт, что HooksServerTLSConfig (default режим —
// server-tls-only, т.к. в деплое нет scrape-клиента с client-cert).
func (m MTLSConfig) MetricsServerTLSConfig() (*tls.Config, error) {
	return serverTLSConfig(m.MetricsServerMTLS, resolveClientAuthMode(m.MetricsClientAuthMode))
}

// JWKSProxyServerTLSConfig возвращает *tls.Config для HTTP jwks-proxy listener
// (:9097). Тот же контракт, что HooksServerTLSConfig, но дефолт — ONE-WAY
// server-tls-only (registry-verifier предъявляет только server-trust, не
// client-cert; mutual сломал бы «verifier untouched»). Default-off → (nil, nil) →
// listener остаётся PLAINTEXT (dev/newman byte-identical).
func (m MTLSConfig) JWKSProxyServerTLSConfig() (*tls.Config, error) {
	return serverTLSConfig(m.JWKSProxyServerMTLS, resolveClientAuthMode(m.JWKSProxyClientAuthMode))
}

// RegistryTokenServerTLSConfig возвращает *tls.Config для HTTP docker-token
// listener (:9096, `/iam/token`). Тот же контракт, что HooksServerTLSConfig;
// дефолт — server-tls-only (caller-auth на этом эндпоинте — сам Basic, не
// client-cert). Default-off → (nil, nil) → listener остаётся PLAINTEXT (dev).
func (m MTLSConfig) RegistryTokenServerTLSConfig() (*tls.Config, error) {
	return serverTLSConfig(m.RegistryTokenServerMTLS, resolveClientAuthMode(m.RegistryTokenClientAuthMode))
}

// RESTServerTLSConfig / InternalRESTServerTLSConfig — транспорт собственных
// REST-фронтов.
func (m MTLSConfig) RESTServerTLSConfig() (*tls.Config, error) {
	return serverTLSConfig(m.RESTServerMTLS, resolveClientAuthMode(m.RESTClientAuthMode))
}

func (m MTLSConfig) InternalRESTServerTLSConfig() (*tls.Config, error) {
	return serverTLSConfig(m.InternalRESTServerMTLS, resolveClientAuthMode(m.InternalRESTClientAuthMode))
}

// RESTUpstreamDialOption — как REST-фронт дозванивается до собственного
// слушателя.
//
// В боевой посадке слушатель требует проверенного клиентского сертификата, и
// фронт предъявляет его наравне со всяким клиентом. Вне боевой — соединение без
// удостоверения, тот же порядок, что у прочих рёбер стенда.
func (m MTLSConfig) RESTUpstreamDialOption() (grpc.DialOption, error) {
	if !m.RESTUpstreamMTLS.Enable {
		return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
	}
	return grpcclient.TLSClientCreds(m.RESTUpstreamMTLS)
}

// Validate проверяет, что каждое включенное ребро несет корректный cert-set под
// свой ClientAuth-режим. Включенное-но-некорректное ребро → fail-closed error на
// старте (aggregated через multierr по ВСЕМ ребрам сразу). Disabled-ребра
// не валидируются (default-off, нулевая регрессия). Вызывается из composition
// root до запуска listener'ов.
//
// gRPC-ребра (public/internal) — всегда mutual-семантика (grpcsrv.TLSServerCreds
// строит RequireAndVerifyClientCert): требуют полный cert-trio. HTTP-ребра
// (hooks/metrics/jwks-proxy/registry-token) — per-edge clientAuthMode:
// server-tls-only нуждается только в
// cert+key (client-CA не нужен), mutual — в полном trio; неизвестный режим —
// ошибка.
func (m MTLSConfig) Validate() error {
	var errs error

	// gRPC server edges — fixed mutual (RequireAndVerifyClientCert) semantics.
	for name, edge := range map[string]grpcsrv.TLSServer{
		"public-server":   m.PublicServerMTLS,
		"internal-server": m.InternalServerMTLS,
	} {
		if !edge.Enable {
			continue
		}
		if err := validateServerEdge(edge, clientAuthMutual); err != nil {
			errs = multierr.Append(errs, fmt.Errorf("%s mTLS edge: %w", name, err))
		}
	}

	// HTTP server edges — per-edge clientAuthMode.
	for name, e := range map[string]struct {
		edge grpcsrv.TLSServer
		mode string
	}{
		"hooks-server":          {m.HooksServerMTLS, resolveClientAuthMode(m.HooksClientAuthMode)},
		"metrics-server":        {m.MetricsServerMTLS, resolveClientAuthMode(m.MetricsClientAuthMode)},
		"jwks-proxy-server":     {m.JWKSProxyServerMTLS, resolveClientAuthMode(m.JWKSProxyClientAuthMode)},
		"registry-token-server": {m.RegistryTokenServerMTLS, resolveClientAuthMode(m.RegistryTokenClientAuthMode)},
		"rest-server":           {m.RESTServerMTLS, resolveClientAuthMode(m.RESTClientAuthMode)},
		"internal-rest-server":  {m.InternalRESTServerMTLS, resolveClientAuthMode(m.InternalRESTClientAuthMode)},
	} {
		if !e.edge.Enable {
			continue
		}
		if err := validateServerEdge(e.edge, e.mode); err != nil {
			errs = multierr.Append(errs, fmt.Errorf("%s mTLS edge: %w", name, err))
		}
	}

	// Удостоверение REST-фронта для СОБСТВЕННОГО слушателя. Половина пары хуже
	// отсутствия обеих: она выглядит настроенной, а отказ даёт на каждом
	// запросе — слушатель отвергает клиента без сертификата, и снаружи исправная
	// служба читается как недоступная.
	if m.RESTUpstreamMTLS.Enable {
		if m.RESTUpstreamMTLS.CertFile == "" || m.RESTUpstreamMTLS.KeyFile == "" {
			errs = multierr.Append(errs, fmt.Errorf(
				"rest-upstream mTLS edge: удостоверение объявлено включённым, а "+
					"сертификат или ключ не заданы — фронт не сможет представиться "+
					"собственному слушателю ни на одном запросе"))
		}
		if len(m.RESTUpstreamMTLS.CAFiles) == 0 {
			errs = multierr.Append(errs, fmt.Errorf(
				"rest-upstream mTLS edge: не задан набор корней — фронту нечем "+
					"проверить сертификат собственного слушателя, и соединение "+
					"либо не состоится, либо состоится без проверки СЕРВЕРА"))
		}
	}
	return errs
}

// validateServerEdge — без чтения файлов проверяет, что enabled-ребро несет
// корректный cert-set под режим mode. Все режимы требуют непустые cert/key.
// mutual дополнительно требует непустой client-CA. Неизвестный mode → fail-closed
// (никогда не трактуется как «без проверок»). Чтение/парсинг — serverTLSConfig.
func validateServerEdge(cfg grpcsrv.TLSServer, mode string) error {
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return fmt.Errorf("enabled but cert_file/key_file is empty (fail-closed)")
	}
	switch mode {
	case clientAuthServerTLSOnly:
		// server-tls-only: client-cert не верифицируется → client-CA не нужен.
		return nil
	case clientAuthMutual, clientAuthOptionalMutual:
		if len(cfg.ClientCAFiles) == 0 {
			return fmt.Errorf("clientAuthMode=%s requires a non-empty client_ca_files (verifying a client cert needs a client CA)", mode)
		}
		return nil
	default:
		return fmt.Errorf("unknown clientAuthMode %q (expected %s|%s|%s)",
			mode, clientAuthServerTLSOnly, clientAuthMutual, clientAuthOptionalMutual)
	}
}

// serverTLSConfig собирает *tls.Config для HTTP-listener'а из per-edge
// grpcsrv.TLSServer value-структуры + resolved clientAuthMode.
// MinVersion TLS1.2 на всех режимах. Возвращает *tls.Config (он уезжает полем
// TLS профиля не-gRPC поверхности) вместо grpc.ServerOption.
//
//   - server-tls-only → ClientAuth=tls.NoClientCert, client-CA не читается;
//   - mutual          → ClientAuth=tls.RequireAndVerifyClientCert + client-CA pool;
//   - неизвестный mode → error (fail-closed — никогда insecure default).
//
// Cert-файлы читаются один раз на старте; ротация = рестарт pod'а (hot-reload
// намеренно вне scope).
func serverTLSConfig(cfg grpcsrv.TLSServer, mode string) (*tls.Config, error) {
	if !cfg.Enable {
		// Default-off: cert-файлы НЕ читаются, listener остается plaintext.
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert/key: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	switch mode {
	case clientAuthServerTLSOnly:
		// Encryption + server-authentication only; no client-cert requested.
		tlsCfg.ClientAuth = tls.NoClientCert
		return tlsCfg, nil
	case clientAuthMutual, clientAuthOptionalMutual:
		if len(cfg.ClientCAFiles) == 0 {
			return nil, fmt.Errorf("clientAuthMode=%s requires a non-empty client_ca_files (verifying a client cert needs a client CA)", mode)
		}
		clientCAs, lerr := loadCAPool(cfg.ClientCAFiles)
		if lerr != nil {
			return nil, fmt.Errorf("load client CA pool: %w", lerr)
		}
		if mode == clientAuthMutual {
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			// Сертификат ЗАПРАШИВАЕТСЯ и верифицируется, если предъявлен.
			// Сам по себе режим ничего не сужает — сужает обработчик, который
			// требует проверенного пира.
			tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
		}
		tlsCfg.ClientCAs = clientCAs
		return tlsCfg, nil
	default:
		return nil, fmt.Errorf("unknown clientAuthMode %q (expected %s|%s|%s)",
			mode, clientAuthServerTLSOnly, clientAuthMutual, clientAuthOptionalMutual)
	}
}

// loadCAPool читает PEM CA-бандлы в x509.CertPool. Пустой/мусорный бандл (нет
// parseable-сертификата) → error (fail-closed).
func loadCAPool(files []string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, f := range files {
		// #nosec G304 -- trusted operator-config path (env KANAME_*_CLIENTCAFILES,
		// mounted internal-CA bundle), not request/user input. Same idiom as
		// снятым дренажом смены субъекта: доверенного корня края владельцу прав больше не нужно.
		pem, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read CA file %q: %w", f, err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no valid PEM certificate in CA file %q", f)
		}
	}
	return pool, nil
}

// HooksTLSEnabled / MetricsTLSEnabled / JWKSProxyTLSEnabled — объявлен ли
// транспорт соответствующего HTTP-ребра.
//
// Существуют затем, чтобы страж старта спрашивал ПОСАДКУ, а не лез в поля:
// поле переедет вместе с формой, а вопрос останется тем же.
func (c MTLSConfig) HooksTLSEnabled() bool { return c.HooksServerMTLS.Enable }

// HooksPlaintextAcknowledged — объявлено ли исключение открытого текста на
// слушателе обратных вызовов. Метод ОДИН на всю посадку намеренно: у остальных
// рёбер исключения не бывает, и спросить о нём нечем (см. поле выше).
func (c MTLSConfig) HooksPlaintextAcknowledged() bool { return c.HooksServerPlaintextAcknowledged }
func (c MTLSConfig) MetricsTLSEnabled() bool          { return c.MetricsServerMTLS.Enable }
func (c MTLSConfig) JWKSProxyTLSEnabled() bool        { return c.JWKSProxyServerMTLS.Enable }

// RESTTLSEnabled / InternalRESTTLSEnabled — объявлен ли транспорт собственных
// REST-фронтов. Спрашивается посадка, а не поле: поле переедет вместе с формой,
// а вопрос останется тем же.
func (c MTLSConfig) RESTTLSEnabled() bool         { return c.RESTServerMTLS.Enable }
func (c MTLSConfig) InternalRESTTLSEnabled() bool { return c.InternalRESTServerMTLS.Enable }

// RESTUpstreamEnabled — объявлено ли удостоверение, которым REST-фронт
// представляется собственному gRPC-слушателю.
func (c MTLSConfig) RESTUpstreamEnabled() bool { return c.RESTUpstreamMTLS.Enable }
