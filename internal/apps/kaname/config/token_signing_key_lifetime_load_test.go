// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// token_signing_key_lifetime_load_test.go — НЕЗАДАННЫЙ срок ключа подписи
// доезжает до стража незаданным (#321).
//
// # Чем эта проба отличается от соседней, и почему без неё та ничего не держит
//
// `token_signing_test.go` мутирует ПОЛЕ СТРУКТУРЫ и зовёт `Validate` — то есть
// судит решение стража на входе, который он получил. О том, бывает ли такой
// вход, она молчит: пока величину подставляет построение, поле не бывает
// нулевым ни при каком профиле, и ветвь стража не исполняется ни разу.
//
// Поэтому здесь проба идёт через `config.Load` — тем путём, которым профиль
// доезжает до службы, — и зовёт тот же страж, что зовёт `Config.Validate`.
//
// # Почему у срока ключа умолчания нет
//
// Срок ключа подписи есть ПОЛИТИКА РОТАЦИИ — решение установки, а не наше.
// Подставленный построением, он не виден тому, кто ставит, и потому не
// пересматривается; а страж, который отвергал бы незаданный, зелен при любом
// входе. Ключ при этом остаётся зарегистрированным с вырожденным значением:
// без регистрации переменная окружения не разрешалась бы вовсе.

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// keyLifetimeKey — координата, которую обязан назвать отказ.
const keyLifetimeKey = "authn.token-signing.key-lifetime"

// profileWithSigningOn — профиль, включающий свою чеканку и задающий ВСЁ её,
// кроме срока ключа, если `lifetime` пуст. Форма — та же, что пишет чарт.
func profileWithSigningOn(lifetime string) string {
	var b strings.Builder
	b.WriteString("authn:\n  token-signing:\n    enabled: true\n")
	b.WriteString("    issuer: \"https://iam.example.invalid\"\n")
	b.WriteString("    algorithm: \"RS256\"\n")
	b.WriteString("    allowed-algorithms: \"RS256\"\n")
	b.WriteString("    key-set-path: \"/.well-known/kaname/jwks.json\"\n")
	if lifetime != "" {
		b.WriteString("    key-lifetime: \"" + lifetime + "\"\n")
	}
	return b.String()
}

// loadSigning — загрузка профиля и настройка чеканки, как её увидит страж.
func loadSigning(t *testing.T, yaml string) config.TokenSigningConfig {
	t.Helper()
	cfg, err := config.Load(writeConfig(t, yaml))
	require.NoError(t, err, "профиль обязан загружаться: предмет пробы — величина, а не разбор")
	return cfg.AuthN.TokenSigning
}

// TestLoadDoesNotSupplyTheSigningKeyLifetime — ОТРИЦАНИЕ: профиль с поднятой
// чеканкой и без срока ключа обязан отвергать пуск, называя ключ.
func TestLoadDoesNotSupplyTheSigningKeyLifetime(t *testing.T) {
	got := loadSigning(t, profileWithSigningOn(""))
	require.Zero(t, got.KeyLifetime,
		"срок ключа, не названный профилем, обязан доехать до стража НЕЗАДАННЫМ: "+
			"подставленный построением, он не бывает нулевым, и ветвь стража не исполняется ни разу")

	err := got.Validate()
	require.Error(t, err, "профиль без срока ключа при поднятой чеканке обязан отвергать пуск")
	require.Contains(t, err.Error(), keyLifetimeKey,
		"отказ обязан назвать КЛЮЧ: оператор читает его, чтобы починить: %v", err)
}

// TestDeclaredSigningKeyLifetimeProfileStarts — ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: тот же
// профиль, отличающийся ровно одним фактом — срок ключа задан.
//
// Без него отрицание выше выполняется тождественно: страж, отвергающий всякий
// профиль, прошёл бы его и не дал бы подняться ни одной установке.
func TestDeclaredSigningKeyLifetimeProfileStarts(t *testing.T) {
	got := loadSigning(t, profileWithSigningOn("2160h"))
	require.Equal(t, 2160*time.Hour, got.KeyLifetime, "названный профилем срок обязан доехать")
	require.NoError(t, got.Validate(), "профиль со сроком ключа обязан стартовать")
}

// TestSigningKeyLifetimeStaysResolvableFromTheEnvironment — снятое умолчание не
// должно стоить разрешения переменной окружения.
//
// `AutomaticEnv` резолвит переменную только для ключа, который випер уже знает.
// Снять регистрацию вместе с умолчанием значило бы закрыть оператору запасной
// путь настройки, не сказав об этом ни слова.
func TestSigningKeyLifetimeStaysResolvableFromTheEnvironment(t *testing.T) {
	t.Setenv("KANAME_AUTHN__TOKEN_SIGNING__KEY_LIFETIME", "720h")

	got := loadSigning(t, profileWithSigningOn(""))
	require.Equal(t, 720*time.Hour, got.KeyLifetime, "переменная окружения обязана разрешаться")
	require.NoError(t, got.Validate())
}
