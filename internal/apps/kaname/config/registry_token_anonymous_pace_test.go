// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// registry_token_anonymous_pace_test.go — темп анонимной выдачи на источник
// (kaname#928) объявляется ЧИСЛОМ, как величины темпа соседних точек
// поверхности выдачи: загрузчик его не подставляет, а страж старта при
// включённом анонимном потоке отказывает, называя ручку.
//
// Проба идёт через настройку службы (переменная → Load → Validate), а не через
// структуру: величина, подставленная загрузчиком, не бывает нулевой, и ветвь
// стража не исполнялась бы ни разу.
package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

const (
	anonPaceEnv = "KANAME_API_SERVER__REGISTRY_TOKEN__ANONYMOUS_PER_SOURCE_PER_SEC"
	anonPaceKey = "api-server.registry-token.anonymous-per-source-per-sec"
)

// loadAnonLane — настройка службы с анонимным принципалом principal и темпом
// pace (пусто — переменная не задана).
func loadAnonLane(t *testing.T, principal, pace string) (config.Config, error) {
	t.Helper()
	t.Setenv(anonServiceEnv, "registry.probe.local")
	t.Setenv(registryIssuerEnv, probeIssuer)
	t.Setenv(anonPrincipalEnv, principal)
	if pace != "" {
		t.Setenv(anonPaceEnv, pace)
	}
	// Доверенный пересыльщик объявлен: предмет этих проб — темп, а поток без
	// пересыльщика страж отвергает отдельно (kaname#930).
	t.Setenv(trustDomainEnv, probeTrustDomain)
	t.Setenv(anonForwarderEnv, registryForwarderSAN)
	cfg, err := config.Load("")
	require.NoError(t, err)
	return cfg, cfg.APIServer.RegistryToken.Validate(cfg.AuthN.ClientToken, cfg.AuthN.TrustDomain())
}

func TestAnonymousPace_LoaderDoesNotSupplyIt(t *testing.T) {
	cfg, _ := loadAnonLane(t, "", "")
	require.Zero(t, cfg.APIServer.RegistryToken.AnonymousPerSourcePerSec,
		"загрузчик подставил темп анонимной выдачи: предел, выбранный за оператора, он не видит")
}

func TestAnonymousPace_UndeclaredWithTheAnonymousLaneRefusesToStartNamingTheKnob(t *testing.T) {
	for name, pace := range map[string]string{"не задан": "", "ноль": "0", "отрицательный": "-1"} {
		t.Run(name, func(t *testing.T) {
			_, err := loadAnonLane(t, "registry-anonymous", pace)
			require.Error(t, err, "анонимный поток без темпа на источник поднялся бы без предела чеканок")
			require.Contains(t, err.Error(), anonPaceKey, "отказ обязан называть ручку: %v", err)
			require.Contains(t, err.Error(), anonPaceEnv, "отказ обязан называть переменную: %v", err)
		})
	}
}

func TestAnonymousPace_DeclaredNumberIsAcceptedAndReachesTheSetting(t *testing.T) {
	cfg, err := loadAnonLane(t, "registry-anonymous", "20")
	require.NoError(t, err)
	require.Equal(t, 20, cfg.APIServer.RegistryToken.AnonymousPerSourcePerSec)
}

func TestAnonymousPace_IsNotRequiredWithoutTheAnonymousLane(t *testing.T) {
	_, err := loadAnonLane(t, "", "0")
	require.NoError(t, err, "страж требует темп потока, которого нет")
}
