// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// registry_token.go — config for the Docker Registry v2 `/iam/token`
// auth-server HTTP listener (the `/iam/token` endpoint only). There is NO JWKS
// endpoint on this listener: the data-plane's Hydra-JWKS verification keys are
// served separately by the cluster-INTERNAL jwks-proxy listener (a caching mirror
// of Hydra's public JWKS — see jwks_proxy.go / internal/handler/jwksproxyhttp).
// Hydra stays the issuer/signer; iam mints nothing here.
//
// The listener is EXTERNAL-reachable (docker clients hit `/iam/token` through
// the edge); TLS is terminated at the ingress, so the process binds plaintext —
// same posture as the hooks / metrics listeners. Policy fields (issuer, service,
// TTL) shape the minted identity-JWT and must match the data-plane's advertised
// Bearer realm.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/audiencepolicy"
)

// Built-in policy defaults. viper also registers them (defaults.go); the
// accessors carry the same fallbacks so an unset struct (tests / partial config)
// still resolves to a valid policy.
//
// АДРЕСАТА (`service`) СРЕДИ НИХ НЕТ, И ЭТО РЕШЕНИЕ, А НЕ ПРОПУСК (задача #1184).
// Имя службы реестра — тенант-фейсинг DNS, оно СВОЁ у каждого кластера, и у
// докерной полосы это имя общее с реестром: он называет его докер-клиенту, мы
// чеканим его в `aud`. Встроенное умолчание здесь было ВТОРЫМ объявлением того
// же предмета, живущим в другом дереве, — и оно молча расходилось с тем, что
// объявляет посадка реестра. Умолчания у величины, которую нельзя выбрать за
// оператора, быть не может: незаданный адресат отвергается стражем старта.
const (
	defaultRegistryTokenIssuer = "https://api.kacho.local/iam/token" // #nosec G101 -- OIDC issuer URL default (iss claim), not a credential
	defaultRegistryTokenTTL    = 5 * time.Minute
)

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

	// KeyMaterialWindowUntilRaw — ОКНО ПЕРЕХОДА ЛОМАЮЩЕГО ИЗМЕНЕНИЯ #1143:
	// мгновение (RFC 3339), до которого докерная полоса ПРОДОЛЖАЕТ принимать
	// ключевой материал в поле пароля наряду с базовым токеном доступа.
	//
	// ENV: KACHO_IAM_API_SERVER__REGISTRY_TOKEN__KEY_MATERIAL_WINDOW_UNTIL
	// Пример значения: 2026-09-30T00:00:00Z
	//
	// УМОЛЧАНИЕ — ПУСТО, ТО ЕСТЬ ОКНО ЗАКРЫТО. Незаданное послабление не
	// означает «принимать оба»: fail-closed.
	//
	// ПРЕДИКАТ СНЯТИЯ ЭТОЙ РУЧКИ вписан в неё саму и состоит из двух частей:
	//   (1) она принимает МГНОВЕНИЕ, а не флажок, поэтому бессрочное окно ею
	//       невыразимо by construction и закрывается временем, а не памятью;
	//   (2) счётчик `kacho_iam_registry_token_credential_kind_total` с меткой
	//       outcome="key_material_accepted_in_window" держит ноль при ненулевой
	//       сумме прочих исходов — значит прежним видом больше не входит никто,
	//       и ручку вместе с восстановленным ради неё проверяющим
	//       (registry_token/sakey_validator.go) снимают одним изменением.
	//
	// Цена обоих умолчаний измерена и названа в
	// registry_token/key_material_window.go — здесь она не пересказывается,
	// чтобы два места об одном предмете не разошлись.
	KeyMaterialWindowUntilRaw string `mapstructure:"key-material-window-until"`
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

// TokenIssuer — the `iss` claim + WWW-Authenticate realm. Falls back to the
// built-in default when unset.
func (c RegistryTokenConfig) TokenIssuer() string {
	if s := strings.TrimSpace(c.Issuer); s != "" {
		return s
	}
	return defaultRegistryTokenIssuer
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

// Validate — страж старта докерной полосы выдачи (задача #1184).
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
func (c RegistryTokenConfig) Validate(clientToken ClientTokenConfig) error {
	// Окно перехода #1143 разбирается СТРАЖЕМ СТАРТА, а не только на пути
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
	if c.TokenService() == "" {
		return fmt.Errorf(
			"api-server.registry-token.service is not declared while the docker lane listener is up (%s) — "+
				"this addressee is not ours to default: it is the registry's own service name, declared once "+
				"by the deployment as global.kacho.registry.serviceAud and read by BOTH sides of the lane "+
				"(the registry ships it as KACHO_REGISTRY_SERVICE_AUD and advertises it to the docker client; "+
				"we mint it into aud). Declare global.kacho.registry.serviceAud, or set this key directly "+
				"when running iam on its own (env KACHO_IAM_API_SERVER__REGISTRY_TOKEN__SERVICE)",
			c.ListenAddress())
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
