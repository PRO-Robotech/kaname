// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// registry_token_audience_guard_test.go — страж старта докерной полосы выдачи
// (задача #1184).
//
// Каждое отрицание идёт в паре с положительным: страж, отвергающий ВСЁ,
// проходил бы по всякому отрицанию и не проверял бы ничего.
package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
)

func platform(audiences string) config.ClientTokenConfig {
	return config.ClientTokenConfig{Enabled: true, AllowedAudiences: audiences, DefaultAudience: "registry.kacho.local"}
}

// TestLaneAudienceMustBeInsideThePlatformDeclaration — адресат, которому
// докерная полоса чеканит, обязан входить в перечень адресатов платформы.
//
// Иначе наш подписант выпускает удостоверение, адресованное поверхности,
// которую посадка не объявляла, — а соседняя полоса тот же адресат отвергает.
// Решал бы это не оператор, а порядок, в котором писались полосы.
func TestLaneAudienceMustBeInsideThePlatformDeclaration(t *testing.T) {
	// ОТРИЦАНИЕ.
	err := config.RegistryTokenConfig{
		Endpoint: "tcp://0.0.0.0:9096", Service: "sts.example.com",
	}.Validate(platform("https://api.kacho.cloud,registry.kacho.local"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "api-server.registry-token.service",
		"отказ обязан назвать настройку — его читает оператор, а не предъявитель")
	require.Contains(t, err.Error(), "authn.client-token.allowed-audiences",
		"и вторую настройку тоже: расхождение чинится сверкой двух объявлений")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: объявленный обеими сторонами адресат проходит.
	require.NoError(t, config.RegistryTokenConfig{
		Endpoint: "tcp://0.0.0.0:9096", Service: "registry.kacho.local",
	}.Validate(platform("https://api.kacho.cloud,registry.kacho.local")))
}

// TestGuardJudgesTheEffectiveAudience — страж судит ДЕЙСТВУЮЩИЙ адресат, а не
// написанное в профиле.
//
// Незаданная настройка резолвится встроенным умолчанием, и токен выйдет
// адресованным ему. Страж, читающий сырое поле, на таком профиле промолчал бы —
// то есть проверял бы текст, а не то, что полоса делает.
func TestGuardJudgesTheEffectiveAudience(t *testing.T) {
	// ОТРИЦАНИЕ: `service` не задан, действует умолчание `registry.kacho.local`,
	// а перечень платформы называет только край.
	err := config.RegistryTokenConfig{Endpoint: "tcp://0.0.0.0:9096"}.
		Validate(platform("https://api.kacho.cloud"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "registry.kacho.local",
		"отказ обязан назвать ДЕЙСТВУЮЩИЙ адресат, а не пустую строку профиля")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: тот же незаданный `service` при перечне, который
	// умолчание называет, проходит.
	require.NoError(t, config.RegistryTokenConfig{Endpoint: "tcp://0.0.0.0:9096"}.
		Validate(platform("https://api.kacho.cloud,registry.kacho.local")))
}

// TestGuardHasNoSubjectWithoutALane — у стража без предмета отказа нет.
//
// Слушателя нет — полосы нет; перечень платформы не объявлен — сверять не с чем,
// и внешней границей полосы остаётся её собственный объявленный адресат.
// Отказ в этих состояниях был бы отказом в старте без предмета.
func TestGuardHasNoSubjectWithoutALane(t *testing.T) {
	require.NoError(t, config.RegistryTokenConfig{Service: "sts.example.com"}.
		Validate(platform("registry.kacho.local")), "слушателя нет — предмета нет")
	require.NoError(t, config.RegistryTokenConfig{
		Endpoint: "tcp://0.0.0.0:9096", Service: "sts.example.com",
	}.Validate(config.ClientTokenConfig{}), "перечень платформы не объявлен — сверять не с чем")

	// Пустой перечень при ВКЛЮЧЁННОМ эндпоинте — предмет соседнего стража, и он
	// о нём говорит сам. Второе сообщение о том же предмете разошлось бы с
	// первым; проба закрепляет, что второго тут нет.
	require.NoError(t, config.RegistryTokenConfig{
		Endpoint: "tcp://0.0.0.0:9096", Service: "sts.example.com",
	}.Validate(config.ClientTokenConfig{Enabled: true, AllowedAudiences: " , "}))
}
