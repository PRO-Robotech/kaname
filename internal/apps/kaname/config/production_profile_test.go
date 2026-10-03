// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// production_profile_test.go — боевой профиль, выполняющий ВСЕ требования
// старта, и его составные части. Фикстура общая для проб пакета: каждая ломает
// ровно свой предмет.
//
// Прежде фикстура жила рядом с пробами словаря посадки личности; словарь снят
// вместе с ключом посадки (kaname#363), и фикстура переехала сюда без параметра
// посадки.
package config_test

import (
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// laneCfg — боевая настройка, удовлетворяющая ВСЕМ требованиям старта, чтобы
// предметом случая осталось ровно то, что случай ломает.
//
// Прежде она принимала посадку личности параметром и выполняла требования обеих
// полос сразу; посадка у службы одна (kaname#363), и параметра больше нет.
func laneCfg() config.Config {
	cfg := goodEndpoints(config.ModeProduction, "require")
	cfg.AuthN.JWKSEncryptionKeyHex = strings.Repeat("ab", 32)
	cfg.AuthN.SecondFactorEncryptionKeyHex = strings.Repeat("cd", 32)
	cfg.AuthN.SelfServiceFreshness = 15 * time.Minute
	cfg.AuthN.TokenSigning = ownMintingSettings()
	// Свой контур выдачи ключей служебных учёток (задача #337): токен-эндпоинт
	// и слушатель, на котором он монтируется.
	cfg.APIServer.RegistryToken = registryTokenLaneSettings()
	cfg.AuthN.ClientToken = clientTokenLaneSettings()
	cfg.AuthN.PresentedCredential = presentedCredentialSettings()
	cfg.AuthN.Login = loginLaneSettings()
	cfg.AuthN.Registration = registrationSettings()
	cfg.AuthN.AccessKeys = accessKeySettings()
	cfg.AuthN.Ceremony = ceremonyLifespanSettings()
	return cfg
}

// registryTokenLaneSettings — поднятый слушатель поверхности выдачи: на нём
// монтируется токен-эндпоинт платформы, и без него включённый эндпоинт
// обслуживать негде. Адресат докерной полосы объявлен и входит в перечень
// адресатов платформы ниже — иначе отказал бы страж докерной полосы.
func registryTokenLaneSettings() config.RegistryTokenConfig {
	return config.RegistryTokenConfig{
		Endpoint: "tcp://0.0.0.0:9096",
		Service:  "registry.kacho.local",
	}
}

// clientTokenLaneSettings — токен-эндпоинт платформы, объявленный полностью:
// величины эндпоинта и темпа поверхности выдачи, каждую стережёт свой страж.
func clientTokenLaneSettings() config.ClientTokenConfig {
	return config.ClientTokenConfig{
		Enabled:                  true,
		AllowedAudiences:         "registry.kacho.local, https://api.kacho.cloud",
		DefaultAudience:          "https://api.kacho.cloud",
		TokenTTL:                 15 * time.Minute,
		BodyCeiling:              64 << 10,
		ExchangesPerClientPerSec: 5,
		InFlightCeiling:          32,
		FailedProofsPerSource:    50,
		FailedProofWindow:        15 * time.Minute,
		AuthorizePerSourcePerSec: 10,
		AuthorizeInFlightCeiling: 32,
	}
}

// accessKeySettings — годная привязка ключей доступа (Ф7 Р2): имя, одно
// происхождение под ним, весь словарь алгоритмов; каждое стережёт свой страж.
func accessKeySettings() config.AccessKeysConfig {
	return config.AccessKeysConfig{
		RPID:       "access.example.invalid",
		Origins:    []string{"https://console.access.example.invalid"},
		Algorithms: []int64{-7, -8, -257},
	}
}

// loginLaneSettings — годная настройка полосы входа (Ф3): значения настоящие,
// каждое стережёт свой страж.
func loginLaneSettings() config.LoginLaneConfig {
	return config.LoginLaneConfig{
		SessionTTL:         24 * time.Hour,
		CookieDomain:       config.CookieDomainNone,
		AddressAttempts:    5,
		AddressWindow:      15 * time.Minute,
		SourceAttempts:     50,
		SourceWindow:       15 * time.Minute,
		PasswordMinLength:  8,
		BreachCheck:        config.BreachCheckDisabled,
		HasherFormat:       "argon2id",
		HasherMemory:       65536,
		HasherIterations:   3,
		HasherParallelism:  4,
		VerifierCapacity:   4,
		MemoryReserveBytes: 256 << 20,
		// Сроки кодов и почтовые ручки Р8 — ориентиры базового профиля
		// (приёмка NTF-2 Р8): их судит страж таблицы границ на любой посадке.
		RecoveryCodeTTL:       ref(15 * time.Minute),
		VerificationCodeTTL:   ref(60 * time.Minute),
		RegistrationCodeTTL:   ref(60 * time.Minute),
		MailWindow:            config.MailWindowsConfig{Recovery: mailWindow(), Verification: mailWindow(), Registration: mailWindow()},
		Attempts:              config.LoginAttemptsConfig{AddressSourcePerWindow: ref(5), Window: ref(15 * time.Minute), AddressFailureCeiling: ref(100)},
		MailThrottledInterval: ref(7 * 24 * time.Hour),
		TrustedDevice:         config.TrustedDeviceConfig{TTL: ref(90 * 24 * time.Hour), RecoveryPerDay: ref(2)},
		// Подтверждение адреса (kaname#456, Р9) — величины профиля продукта.
		VerificationCodeAttempts:   5,
		VerificationResendInterval: 60 * time.Second,
		VerificationResendLimit:    5,
		VerificationResendWindow:   24 * time.Hour,
	}
}

// ref — указатель на значение: ручки таблицы границ объявлены указателями,
// чтобы «не объявлено» отличалось от нуля.
func ref[T any](v T) *T { return &v }

// mailWindow — окно адресата базового профиля (Р8): 60s · 5m · 3/ч · 5/сут ·
// пол 6h.
func mailWindow() config.MailWindowConfig {
	return config.MailWindowConfig{
		FirstPause: ref(60 * time.Second), SecondPause: ref(5 * time.Minute),
		PerHour: ref(3), PerDay: ref(5), FloorInterval: ref(6 * time.Hour),
	}
}

// inviteSettings — величины приглашения базового профиля (Р8).
func inviteSettings() config.InviteConfig {
	return config.InviteConfig{
		TTL: ref(7 * 24 * time.Hour), AccountPerDay: ref(200), YoungAccountPerDay: ref(50),
		YoungAccountAge: ref(30 * 24 * time.Hour), PendingMax: ref(200),
		RecipientPerHour: ref(3), RecipientPerDay: ref(5), RecipientPerDayAll: ref(10),
		MailRateLimit: config.InviteMailRateLimitConfig{
			MaxPerWindow: config.DefaultInviteMailPerWindow,
			Window:       config.DefaultInviteMailWindow,
		},
	}
}

// presentedCredentialSettings — валидная настройка приёма предъявленного.
// Значения настоящие, а не заглушка: приём проверяется собственным стражем в
// любом режиме.
func presentedCredentialSettings() config.PresentedCredentialConfig {
	return config.PresentedCredentialConfig{
		Enabled:            true,
		Audience:           "kaname-public",
		RevocationCacheTTL: 30 * time.Second,
	}
}

// ownMintingSettings — валидная настройка своей чеканки. Своя чеканка
// проверяется собственным стражем в любом режиме, поэтому её значения обязаны
// быть настоящими, а не заглушкой.
func ownMintingSettings() config.TokenSigningConfig {
	return config.TokenSigningConfig{
		Enabled:           true,
		Issuer:            "https://iam.kacho.cloud",
		Algorithm:         "RS256",
		AllowedAlgorithms: "RS256",
		KeySetPath:        "/.well-known/kaname/jwks.json",
		KeyLifetime:       90 * 24 * time.Hour,
	}
}
