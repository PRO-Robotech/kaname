// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// jwks_proxy.go — config for the cluster-INTERNAL key-set publisher HTTP
// listener.
//
// ─────────────────────────────────────────────────────────────────────────────
// THE PUBLISHER SERVES TWO RECORDS, ONE PER ISSUER — не одну
//
// Здесь стояло «Hydra stays the token issuer/signer (iam mints nothing)». Это
// утверждение ПЕРЕЖИЛО СВОЙ ПРЕДМЕТ, и стояло оно в месте, которое читают при
// всяком разборе выдачи: по нему искали причину не там.
//
// Что верно сегодня — и проверяется композиционным корнем, а не этим текстом
// (`cmd/kaname/serve.go`, сборка records для jwksproxyhttp.NewBinding):
//
//	запись               путь                                     чьи ключи
//	───────────────────  ───────────────────────────────────────  ──────────────
//	зеркало провайдера   `GET /.well-known/jwks.json`             провайдера
//	наша                 authn.token-signing.key-set-path         ключница iam
//	                     (умолчание `/.well-known/kaname/jwks.json`)
//
// Наша запись публикуется, когда поднята ключница (`authn.token-signing`);
// источник её — jwksproxyhttp.NewKeySetHandler поверх signingkeystore. Значит
// платформа СВОЙ набор ключей имеет и свои токены подписывает сама.
//
// Записи заведены раздельно НАМЕРЕННО. Объединить наборы в один документ было
// бы дешевле и уничтожило бы ровно ту защиту, ради которой развязка «издатель →
// источник набора» существует: ключ одного издателя проверял бы токен,
// объявляющий другого. Зеркало остаётся на прежнем пути до конца перехода — его
// адрес объявлен у каждого сегодняшнего потребителя.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ОСТАЛОСЬ ЗА ПРОВАЙДЕРОМ — и это НЕ остаток уборки
//
// Интерактивный вход человека (`authorization_code`) держится на провайдере
// целиком: наш токен-эндпоинт принимает ровно два вида выдачи —
// `client_credentials` и `jwt-bearer` (`handler/clienttokenhttp`), и вида
// `authorization_code` среди них нет. Плюс удостоверения ПРЕЖНЕГО выпуска
// живут до собственного истечения. Поэтому провайдер остаётся издателем и
// подписантом — СВОЕЙ записи, а не единственным на платформе.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗЕРКАЛО
//
// Зеркало — кэширующий обратный прокси ПУБЛИЧНОГО набора провайдера с коротким
// сроком: плоскость данных (kacho-registry) берёт ключи проверки у iam, а не
// звонит провайдеру напрямую. Верхний хоп резолвится
// AuthNConfig.ResolveHydraJWKSURL (env KANAME_HYDRA_JWKS_URL).
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
