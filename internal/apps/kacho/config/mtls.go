// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"go.uber.org/multierr"
	"google.golang.org/grpc"

	corecfg "github.com/PRO-Robotech/kacho/pkg/config"
	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

// mtlsEnvPrefix — корневой сегмент env-имен для per-edge server-side mTLS.
// LoadPrefixed (envconfig) выводит env-имя каждого поля из иерархии:
// mtlsEnvPrefix + tag родительского поля + field примитива →
// KACHO_IAM_<EDGE>_<NAME>.
const mtlsEnvPrefix = "KACHO_IAM"

// MTLSConfig — per-edge opt-in server-side mTLS для listener'ов IAM (+
// HTTP-listener hardening). Загружается ОТДЕЛЬНО от основного
// viper-конфига через envconfig (LoadMTLS) — grpcsrv.TLSServer это
// горизонтальная corelib value-структура без mapstructure-тегов; envconfig
// обрабатывает ее поля напрямую.
//
// IAM — leaf-owner ресурсной модели (vpc/compute/nlb дилят IAM как клиенты, сам
// IAM исходящих peer-дилов на ресурсы не делает), поэтому здесь только
// server-edges. subject_change-drainer → api-gateway internal — отдельный
// client-edge, конфигурируется в composition root (cmd/kacho-iam/
// subject_change_wiring.go) и вне scope.
//
// Каждое ребро независимо: env-имена выводятся из тега родительского поля.
// Напр. InternalServerMTLS → KACHO_IAM_INTERNAL_SERVER_MTLS_{ENABLE,CERTFILE,
// KEYFILE,CLIENTCAFILES}. Enable=false (default) → insecure/plaintext (dev
// backward-compat). Per-edge enable → независимый rollback.
//
// Четыре server-edge'а:
//   - PublicServerMTLS   — gRPC public listener (:9090), grpc.ServerOption.
//   - InternalServerMTLS — gRPC internal listener (:9091), grpc.ServerOption.
//   - HooksServerMTLS    — HTTP Hydra/Kratos hooks listener (:9092), *tls.Config.
//   - MetricsServerMTLS  — HTTP Prometheus /metrics listener (:9095), *tls.Config.
//
// gRPC-ребра отдают grpc.ServerOption (передается в grpcsrv.NewServer);
// HTTP-ребра отдают *tls.Config (оборачивает net.Listener через tls.NewListener
// в composition root). Default-off у HTTP-ребер → builder возвращает (nil, nil)
// → listener остается PLAINTEXT, byte-identical к текущему поведению.
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

	// HooksClientAuthMode — per-edge TLS ClientAuth-режим для hooks-listener'а
	// (:9092). Env: KACHO_IAM_HOOKS_SERVER_MTLS_CLIENTAUTHMODE. Допустимые
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
	// (:9095). Env: KACHO_IAM_METRICS_SERVER_MTLS_CLIENTAUTHMODE. Пустая строка
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
	// KACHO_IAM_JWKSPROXY_SERVER_MTLS_{ENABLE,CERTFILE,KEYFILE,CLIENTCAFILES}.
	JWKSProxyServerMTLS grpcsrv.TLSServer `envconfig:"JWKSPROXY_SERVER_MTLS"`

	// JWKSProxyClientAuthMode — per-edge TLS ClientAuth-режим для jwks-proxy
	// listener'а (:9097). Env: KACHO_IAM_JWKSPROXY_SERVER_MTLS_CLIENTAUTHMODE.
	// Пустая строка (unset) при enabled-edge → безопасный per-edge дефолт
	// server-tls-only (ONE-WAY: registry-verifier предъявляет только server-trust,
	// не client-cert — mutual сломал бы «verifier untouched»). Неизвестный режим →
	// fail-closed.
	JWKSProxyClientAuthMode string `envconfig:"JWKSPROXY_SERVER_MTLS_CLIENTAUTHMODE"`
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
)

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

// LoadMTLS читает per-edge server-side mTLS-конфиг из env (KACHO_IAM_*).
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
// который composition root оборачивает через tls.NewListener.
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

// Validate проверяет, что каждое включенное ребро несет корректный cert-set под
// свой ClientAuth-режим. Включенное-но-некорректное ребро → fail-closed error на
// старте (aggregated через multierr для всех четырех ребер сразу). Disabled-ребра
// не валидируются (default-off, нулевая регрессия). Вызывается из composition
// root до запуска listener'ов.
//
// gRPC-ребра (public/internal) — всегда mutual-семантика (grpcsrv.TLSServerCreds
// строит RequireAndVerifyClientCert): требуют полный cert-trio. HTTP-ребра
// (hooks/metrics) — per-edge clientAuthMode: server-tls-only нуждается только в
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
		"hooks-server":      {m.HooksServerMTLS, resolveClientAuthMode(m.HooksClientAuthMode)},
		"metrics-server":    {m.MetricsServerMTLS, resolveClientAuthMode(m.MetricsClientAuthMode)},
		"jwks-proxy-server": {m.JWKSProxyServerMTLS, resolveClientAuthMode(m.JWKSProxyClientAuthMode)},
	} {
		if !e.edge.Enable {
			continue
		}
		if err := validateServerEdge(e.edge, e.mode); err != nil {
			errs = multierr.Append(errs, fmt.Errorf("%s mTLS edge: %w", name, err))
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
	case clientAuthMutual:
		if len(cfg.ClientCAFiles) == 0 {
			return fmt.Errorf("clientAuthMode=mutual requires a non-empty client_ca_files (RequireAndVerifyClientCert needs a client CA)")
		}
		return nil
	default:
		return fmt.Errorf("unknown clientAuthMode %q (expected %s|%s)", mode, clientAuthServerTLSOnly, clientAuthMutual)
	}
}

// serverTLSConfig собирает *tls.Config для HTTP-listener'а из per-edge
// grpcsrv.TLSServer value-структуры + resolved clientAuthMode.
// MinVersion TLS1.2 на всех режимах. Возвращает *tls.Config (для http.Server /
// tls.NewListener) вместо grpc.ServerOption.
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
	case clientAuthMutual:
		if len(cfg.ClientCAFiles) == 0 {
			return nil, fmt.Errorf("clientAuthMode=mutual requires a non-empty client_ca_files (RequireAndVerifyClientCert needs a client CA)")
		}
		clientCAs, lerr := loadCAPool(cfg.ClientCAFiles)
		if lerr != nil {
			return nil, fmt.Errorf("load client CA pool: %w", lerr)
		}
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		tlsCfg.ClientCAs = clientCAs
		return tlsCfg, nil
	default:
		return nil, fmt.Errorf("unknown clientAuthMode %q (expected %s|%s)", mode, clientAuthServerTLSOnly, clientAuthMutual)
	}
}

// loadCAPool читает PEM CA-бандлы в x509.CertPool. Пустой/мусорный бандл (нет
// parseable-сертификата) → error (fail-closed).
func loadCAPool(files []string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, f := range files {
		// #nosec G304 -- trusted operator-config path (env KACHO_IAM_*_CLIENTCAFILES,
		// mounted internal-CA bundle), not request/user input. Same idiom as
		// cmd/kacho-iam/subject_change_wiring.go gateway-CA read.
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
