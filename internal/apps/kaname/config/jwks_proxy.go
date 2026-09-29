// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// jwks_proxy.go — config for the cluster-INTERNAL key-set publisher HTTP
// listener.
//
// ─────────────────────────────────────────────────────────────────────────────
// THE PUBLISHER SERVES ONE RECORD — НАШ набор
//
// Что верно сегодня — и проверяется композиционным корнем, а не этим текстом
// (`cmd/kaname/serve.go`, сборка records для jwksproxyhttp.NewBinding):
//
//	запись   путь                                     чьи ключи
//	───────  ───────────────────────────────────────  ──────────────
//	наша     authn.token-signing.key-set-path         ключница iam
//	         (умолчание `/.well-known/kaname/jwks.json`)
//
// Запись публикуется, когда поднята ключница (`authn.token-signing`); источник
// её — jwksproxyhttp.NewKeySetHandler поверх signingkeystore. Платформа свой
// набор ключей имеет и свои токены подписывает сама.
//
// Прежде рядом стояла вторая запись — зеркало публичного набора прежнего
// издателя на пути `/.well-known/jwks.json` с верхним хопом к нему. Оно ушло
// вместе с внешним издателем (kaname#361), и привязка отвергает вторую запись
// в старте: объединять наборы разных издателей в один документ запрещено, а
// ставить их рядом больше не для кого.
//
// Слушатель выставлен ТОЛЬКО на внутренний Service `kaname-internal` (никогда
// наружу, ban #6) по односторонней server-TLS (лист внутреннего CA); провязка
// Service живёт в чарте развёртывания.
package config

// JWKSProxyConfig — api-server.jwks-proxy section.
//
//	Endpoint — HTTP listen address (`tcp://0.0.0.0:9097` or bare `9097`).
//	           Empty disables the listener.
type JWKSProxyConfig struct {
	Endpoint string `mapstructure:"endpoint"`
}

// ListenAddress — normalised listen-addr for the JWKS-proxy HTTP server (empty
// endpoint → empty, i.e. the listener is disabled). A SEPARATE cluster-internal
// port from the gRPC / hooks / metrics / registry-token listeners.
func (c JWKSProxyConfig) ListenAddress() string { return listenAddress(c.Endpoint) }
