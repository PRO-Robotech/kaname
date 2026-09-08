// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// authn_phase2.go — helpers for the AuthN core config fields.
//
// Reading order:
//
//  1. value from YAML/ENV directly (e.g. authn.hook-shared-secret),
//  2. ENV variable referenced by authn.hook-shared-secret-env (default
//     KANAME_HOOK_TOKEN). Required because secrets are never written to
//     YAML (workspace policy — secretKeyRef-only).
//
// ResolveHydraIssuer() / ResolveAudience() — derived from Domain. Умолчания у
// Domain нет: см. ResolveDomain.
//
// All methods are pure (no side-effects; only os.Getenv reads).
package config

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/keywrap"
)

// ResolveHookSharedSecret returns the current shared-secret for Hydra hooks.
// If authn.hook-shared-secret is set directly (dev) we use it; otherwise we
// read the ENV variable named by authn.hook-shared-secret-env.
//
// Пустой возврат ОБХОДА НЕ ДАЁТ. Обработчик отвечает на него `500`
// `hook_secret_not_configured` и не обслуживает запрос: ненастроенный секрет —
// операторская ошибка нашей стороны, а не «аутентификация не требуется»
// (`internal/handler/iamhooks/hook_auth.go`, проба
// `TestHookAuthUnconfiguredSecretIsObservable`). В production-посадке пустое
// значение до обработчика вообще не доезжает — страж старта отказывает в пуске
// (`validateProductionAuthNSecrets`).
func (c AuthNConfig) ResolveHookSharedSecret() string {
	if c.HookSharedSecret != "" {
		return c.HookSharedSecret
	}
	envName := c.HookSharedSecretEnv
	if envName == "" {
		envName = "KANAME_HOOK_TOKEN"
	}
	return os.Getenv(envName)
}

// JWKSEncryptionKeyEnvName — имя переменной окружения, из которой берётся ключ
// ОБЁРТКИ приватной половины, когда ручка не задана значением напрямую.
//
// Объявлено ОДНИМ местом: имя переменной называют текст отказа резолва, текст
// отказа старта при смене ключа и сам резолв. Три копии разошлись бы молча — на
// той, которую забыли поправить, и оператор искал бы не ту переменную.
func (c AuthNConfig) JWKSEncryptionKeyEnvName() string {
	if n := strings.TrimSpace(c.JWKSEncryptionKeyHexEnv); n != "" {
		return n
	}
	return "KANAME_JWKS_ENC_KEY"
}

// ResolveJWKSEncryptionKeys возвращает ПЕРЕЧЕНЬ ключей ОБЁРТКИ приватной
// половины подписного ключа, декодированный из hex: ПЕРВЫЙ оборачивает, ВСЕ
// открывают.
//
// Источник: authn.jwks-encryption-key-hex напрямую либо переменная окружения,
// названная authn.jwks-encryption-key-hex-env (по умолчанию
// KANAME_JWKS_ENC_KEY). Каждая запись обязана быть ровно ключом объявленного
// размера.
//
// # Почему перечень, а не вторая ручка (задача #1065)
//
// У ключа обёртки обязан быть путь смены. Одно значение его не даёт вовсе:
// новое не открывает ни одной уже записанной приватной половины. Перечень даёт
// смену без простоя и без переписывания хранилища — новый ключ встаёт первым,
// прежний остаётся для чтения.
//
// Второй ручки не заводится по той же причине, по какой её не завели прежде:
// одна из двух неизбежно оказалась бы необязательной, и профиль развёртывания,
// задавший «не ту», выглядел бы настроенным. Перечень из одного — сегодняшнее
// значение всякого профиля, и ни один из них не меняется.
//
// # Разделитель и вырожденное значение
//
// Читается общим предикатом перечней настройки (ParseCommaList): считаются
// ЭЛЕМЕНТЫ, а не длина строки. Свой предикат разошёлся бы с общим ровно на
// вырожденном значении — одинокая запятая даёт длину 1 и ноль элементов, — и
// служба поднялась бы без ключа обёртки вовсе.
//
// # Повтор значения отвергается
//
// Повтор означает смену, которой не было: оператор считает ключ сменённым, а
// обёрнуто и открывается всё тем же. Приняв его молча, мы получили бы число
// названных ключей, не равное числу ключей, которыми что-то можно открыть, —
// и печатаемая при старте величина начала бы лгать.
//
// # У этой ручки снова есть потребитель — и он ЕДИНСТВЕННЫЙ
//
// Ею оборачивается приватная половина подписного ключа в ключнице
// (internal/keywrap, задача #897). Приватная половина ложится в базу, класть её
// открытым текстом нельзя, значит ключ обёртки нужен по существу — вопрос был
// лишь в том, сколько ручек об одном предмете окажется в конфигурации.
//
// Второй ручки не заводится намеренно: две ручки об одном предмете дают ту, что
// неизбежно окажется необязательной, и профиль развёртывания, задавший «не ту»,
// выглядел бы настроенным. Форма совпадает — страж уже требовал ровно 32 байта,
// то есть размер ключа симметричного шифра, которым обёртка и делается.
//
// Имя ручки НЕ переименовано осознанно: переименование стоило бы правки каждого
// профиля развёртывания и дало бы окно, в котором старое имя молча
// игнорируется. Сменился смысл, и он записан здесь.
func (c AuthNConfig) ResolveJWKSEncryptionKeys() ([][]byte, error) {
	raw := c.JWKSEncryptionKeyHex
	if raw == "" {
		raw = os.Getenv(c.JWKSEncryptionKeyEnvName())
	}
	entries := ParseCommaList(raw)
	if len(entries) == 0 {
		return nil, fmt.Errorf("authn.jwks-encryption-key-hex is empty (set ENV %s)", c.JWKSEncryptionKeyEnvName())
	}
	// Размер ключа берётся у обёртки, а не из своей копии: два числа об одном
	// предмете разошлись бы так, что страж пропускал бы то, чем обернуть нельзя.
	keys := make([][]byte, 0, len(entries))
	seen := make(map[string]int, len(entries))
	for i, entry := range entries {
		key, err := hex.DecodeString(entry)
		if err != nil {
			return nil, fmt.Errorf("authn.jwks-encryption-key-hex: entry #%d of %d: invalid hex: %w",
				i+1, len(entries), err)
		}
		if len(key) != keywrap.KeySize {
			return nil, fmt.Errorf("authn.jwks-encryption-key-hex: entry #%d of %d must decode to %d bytes (got %d)",
				i+1, len(entries), keywrap.KeySize, len(key))
		}
		// Значение НЕ попадает в текст отказа ни при каком исходе — оператору
		// называется позиция, предъявителю не называется ничего.
		if first, dup := seen[string(key)]; dup {
			return nil, fmt.Errorf(
				"authn.jwks-encryption-key-hex: entry #%d of %d repeats entry #%d — a repeated wrapping key is a change that did not happen",
				i+1, len(entries), first)
		}
		seen[string(key)] = i + 1
		keys = append(keys, key)
	}
	return keys, nil
}

// ResolveDomain — доменное имя посадки, объявленное оператором. Умолчания НЕТ:
// пустое значение означает «не объявлено» и доезжает до стража старта.
//
// Прежде здесь стоял литерал доменного имени платформы. Он был не косметикой:
// из этого значения выводится клеймо АДРЕСАТА, уезжающее в каждом выпущенном
// удостоверении, — то есть подставленное построением имя чужого продукта
// адресовало удостоверения не туда на всякой посадке, ни одна из которых
// значения не объявляла. Поставщик теперь есть у профиля (чарт), а незаданное
// значение отвергает страж (`validateDeclaredDomain`).
func (c AuthNConfig) ResolveDomain() string {
	return strings.TrimSpace(c.Domain)
}

// ResolveHydraIssuer returns the Hydra issuer. Precedence: explicit HydraIssuer
// field → KANAME_HYDRA_ISSUER env → derived `https://hydra.<Domain>`. The env
// fallback lets a deployment whose Hydra advertises a non-derivable issuer (e.g. a
// dev-stand behind a path-prefixed public URL) align the shim's client_assertion
// audience with Hydra's real issuer — otherwise the exchange fails invalid_client.
func (c AuthNConfig) ResolveHydraIssuer() string {
	if iss := strings.TrimSpace(c.HydraIssuer); iss != "" {
		return iss
	}
	if v := strings.TrimSpace(os.Getenv("KANAME_HYDRA_ISSUER")); v != "" {
		return v
	}
	return "https://hydra." + c.ResolveDomain()
}

// ResolveAudience returns the caller-aud for tokens (`<domain>` without
// scheme). Used by token_hook to embed the audience claim.
func (c AuthNConfig) ResolveAudience() string {
	return c.ResolveDomain()
}

// ResolveHydraAdminURL — URL of the Hydra admin API (client-registration +
// jwt-bearer trust-grants). Precedence: the explicit `authn.hydra-admin-url` /
// ENV KANAME_HYDRA_ADMIN_URL override, then the derivation from the issuer
// (hydra.X → hydra-admin.X). The override lets in-cluster iam reach the
// cluster-internal admin Service (http://kacho-umbrella-hydra-admin.<ns>.svc:4445)
// even when the external issuer host does not resolve in-cluster.
// DeclaredHydraAdminURL returns the admin-API address an operator actually
// WROTE — the YAML setting or its ENV override — and the empty string when
// neither is set.
//
// It exists because ResolveHydraAdminURL below never returns empty: it falls back
// to a derivation from the issuer. That makes "declared" and "guessed"
// indistinguishable at the call sites, which is precisely what let a production
// profile ship with no declaration at all. The production boot guard
// (config.validateProductionProviderAdminHop) reads THIS, not the resolved value.
func (c AuthNConfig) DeclaredHydraAdminURL() string {
	if v := strings.TrimSpace(c.HydraAdminURL); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("KANAME_HYDRA_ADMIN_URL"))
}

// ResolveHydraAdminCAFile — path to the PEM bundle the provider-admin hop is
// verified against. Explicit setting, then ENV; empty when neither is set.
//
// Deliberately NOT derived from any other path: an anchor that is always
// non-empty would make the hop read as verified on a profile that never
// configured one, which is the same defect as a derived address.
func (c AuthNConfig) ResolveHydraAdminCAFile() string {
	if v := strings.TrimSpace(c.HydraAdminCAFile); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("KANAME_HYDRA_ADMIN_CA_FILE"))
}

func (c AuthNConfig) ResolveHydraAdminURL() string {
	if v := c.DeclaredHydraAdminURL(); v != "" {
		return v
	}
	if iss := c.ResolveHydraIssuer(); iss != "" {
		u, err := url.Parse(iss)
		if err == nil {
			// hydra.X.Y → hydra-admin.X.Y (Hydra split public/admin convention).
			if h := u.Hostname(); strings.HasPrefix(h, "hydra.") {
				u.Host = "hydra-admin." + strings.TrimPrefix(h, "hydra.")
				if p := u.Port(); p != "" {
					u.Host += ":" + p
				}
				return u.String()
			}
		}
	}
	return "https://hydra-admin." + c.ResolveDomain()
}

// ResolveHydraTokenEndpoint — the EXTERNAL issuer's token endpoint
// (`<issuer>/oauth2/token`). This is the value Hydra recognises as the audience
// of a client_assertion, and stays external regardless of the cluster-internal
// POST target.
func (c AuthNConfig) ResolveHydraTokenEndpoint() string {
	return strings.TrimRight(c.ResolveHydraIssuer(), "/") + "/oauth2/token"
}

// ResolveHydraTokenURL — the Hydra public token endpoint the `/iam/token` shim
// POSTs the exchange to. Precedence: the explicit `authn.hydra-token-url` / ENV
// KANAME_HYDRA_TOKEN_URL override (a cluster-internal Service, e.g.
// http://kacho-umbrella-hydra-public.<ns>.svc:4444/oauth2/token), then the
// external token endpoint (back-compat). The `iss` of the resulting token remains
// the external Hydra issuer; only the network target differs.
func (c AuthNConfig) ResolveHydraTokenURL() string {
	if v := c.DeclaredHydraTokenURL(); v != "" {
		return v
	}
	return c.ResolveHydraTokenEndpoint()
}

// DeclaredHydraTokenURL / DeclaredHydraJWKSURL return the address an operator
// actually WROTE — the YAML setting or its ENV override — and the empty string
// when neither is set.
//
// They exist for the same reason DeclaredHydraAdminURL does: the Resolve* form
// never returns empty, so "declared" and "guessed" are indistinguishable at the
// call sites, and the guessed value is the PUBLIC ingress hostname. The
// production boot guard (validateProductionProviderPublicHops) reads THESE, not
// the resolved values.
func (c AuthNConfig) DeclaredHydraTokenURL() string {
	if v := strings.TrimSpace(c.HydraTokenURL); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("KANAME_HYDRA_TOKEN_URL"))
}

func (c AuthNConfig) DeclaredHydraJWKSURL() string {
	if v := strings.TrimSpace(c.HydraJWKSURL); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("KANAME_HYDRA_JWKS_URL"))
}

// ResolveHydraTokenCAFile / ResolveHydraJWKSCAFile — path to the PEM bundle each
// hop to the provider's PUBLIC listener is verified against. Explicit setting,
// then ENV; empty when neither is set.
//
// Deliberately NOT derived from any other path (not even from the admin hop's
// anchor, which happens to be the same bundle today): an anchor that is always
// non-empty would make the hop read as verified on a profile that never
// configured one — the same defect as a derived address.
func (c AuthNConfig) ResolveHydraTokenCAFile() string {
	if v := strings.TrimSpace(c.HydraTokenCAFile); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("KANAME_HYDRA_TOKEN_CA_FILE"))
}

func (c AuthNConfig) ResolveHydraJWKSCAFile() string {
	if v := strings.TrimSpace(c.HydraJWKSCAFile); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("KANAME_HYDRA_JWKS_CA_FILE"))
}

// ResolveHydraJWKSURL — the upstream Hydra PUBLIC JWKS URL the cluster-internal
// jwks-proxy listener mirrors (`GET /.well-known/jwks.json`). Precedence mirrors
// ResolveHydraTokenURL: the explicit `authn.hydra-jwks-url` / ENV
// KANAME_HYDRA_JWKS_URL override (a cluster-internal Service, e.g.
// http://kacho-umbrella-hydra-public.<ns>.svc:4444/.well-known/jwks.json), then the
// derived `<issuer>/.well-known/jwks.json` (back-compat). Hydra remains the signer;
// iam serves a byte-identical mirror so the served kids are Hydra's real signing
// kids (iam has no keyset of its own — it mints nothing). Only the network target
// differs — the `iss` of a verified token stays the external Hydra issuer.
func (c AuthNConfig) ResolveHydraJWKSURL() string {
	if v := c.DeclaredHydraJWKSURL(); v != "" {
		return v
	}
	return strings.TrimRight(c.ResolveHydraIssuer(), "/") + "/.well-known/jwks.json"
}

// HooksHTTPListenAddress — normalised listen-addr for the webhook HTTP
// server. Default `tcp://0.0.0.0:9092` (separate port from gRPC
// public/internal).
func (c AuthNConfig) HooksHTTPListenAddress() string {
	return listenAddress(c.HooksHTTPEndpoint)
}

// HydraAdminTokenEnvName — имя переменной окружения, из которой берётся
// административный предъявитель внешнего поставщика.
//
// Объявлено ОДНИМ местом: его называют резолв, текст документации профиля и
// перепись ручек разговора с поставщиком. Три копии разошлись бы молча — на
// той, которую забыли поправить.
func (c AuthNConfig) HydraAdminTokenEnvName() string {
	if n := strings.TrimSpace(c.HydraAdminTokenEnv); n != "" {
		return n
	}
	return "KANAME_HYDRA_ADMIN_TOKEN"
}

// ResolveHydraAdminToken возвращает административный предъявитель внешнего
// поставщика.
//
// Пустая строка — законное значение: административный порт поставщика в этой
// посадке не аутентифицирует никого, и требовать предъявителя значило бы не
// пустить в старт каждый существующий стенд. Ценность резолва не в требовании,
// а в ВИДИМОСТИ: ручка, читаемая здесь, видна проверке настройки; ручка,
// читаемая в корне сборки, — нет.
func (c AuthNConfig) ResolveHydraAdminToken() string {
	return strings.TrimSpace(os.Getenv(c.HydraAdminTokenEnvName()))
}
