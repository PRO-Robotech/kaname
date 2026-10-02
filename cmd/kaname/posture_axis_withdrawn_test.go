// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// posture_axis_withdrawn_test.go — КОРЕНЬ НЕ ВЫБИРАЕТ ПОЛОСУ ПО КЛЮЧУ ПОСАДКИ
// (kaname#363).
//
// Прежде корень выводил полосу из значения ключа посадки, и незаданное значение
// читалось как «не own»: в режиме разработчика на пустом профиле он поднимал
// хуки внешнего поставщика и строил к нему административную дорогу, а полосу
// своего входа не требовал вовсе. Ключа больше нет, и полоса у корня одна.
//
// Три наблюдения, у каждого законный близнец:
//
//	поверхности  перечень, выведенный из объявлений корня, не называет
//	             поверхности хуков; близнец — тот же перечень называет
//	             полосу входа, объявленную тем же способом;
//	самоотчёт    строка провязки полосы не докладывает о дороге к поставщику;
//	             близнец — та же строка докладывает о подписанте;
//	полоса входа боевой корень без ключа посадки требует TLS слушателя полосы
//	             входа; близнец — тот же корень с объявленным TLS проходит.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/tools/surfaceroster"
)

// retiredHooksSettingKey — ключ адреса поверхности хуков внешнего поставщика,
// как его выводит перечень поверхностей. Литерал: проба судит, что корень не
// объявляет ИМЕННО эту поверхность, и не должна уйти вслед за переименованием.
const retiredHooksSettingKey = "authn.hooks-http-endpoint"

// loginLaneSettingKey — ключ адреса полосы входа: поверхность того же вида,
// объявленная корнем тем же способом, — законный близнец.
const loginLaneSettingKey = "api-server.login-lane-endpoint"

func rootSurfaceKeys(t *testing.T) (map[string]bool, surfaceroster.Roster) {
	t.Helper()
	root, err := surfaceroster.IAMRoot(".")
	require.NoError(t, err, "корень дерева службы")
	roster, err := surfaceroster.Read(root)
	require.NoError(t, err, "перечень поверхностей")
	require.NotEmpty(t, roster.Surfaces, "перечень поверхностей пуст — вердикт был бы о пустоте")
	keys := map[string]bool{}
	for _, s := range roster.Surfaces {
		keys[s.SettingKey] = true
	}
	return keys, roster
}

func TestRootDeclaresNoProviderHooksSurface(t *testing.T) {
	keys, roster := rootSurfaceKeys(t)
	t.Logf("перепись: файлов прочитано %d · поверхностей %d", roster.FilesRead, len(roster.Surfaces))
	require.Falsef(t, keys[retiredHooksSettingKey],
		"корень объявляет поверхность хуков внешнего поставщика (%s): у службы одна посадка, "+
			"поставщика нет, и дверь держала бы в работе маршруты, которые обслуживают никого",
		retiredHooksSettingKey)
}

// Законный близнец: перечень, выведенный тем же разбором, называет полосу
// входа — поверхность того же вида. Без него молчание выше читалось бы как
// «перечень не читает объявлений корня».
func TestRootDeclaresTheSignInLaneSurface(t *testing.T) {
	keys, _ := rootSurfaceKeys(t)
	require.Truef(t, keys[loginLaneSettingKey],
		"перечень поверхностей не называет полосу входа (%s) — разбор не видит объявлений корня", loginLaneSettingKey)
}

func TestLaneWiringCensusNamesNoProviderRoad(t *testing.T) {
	census := laneWiringCensus(config.LaneWiring{})
	for i := 0; i+1 < len(census); i += 2 {
		key, _ := census[i].(string)
		require.NotContainsf(t, key, "provider",
			"строка провязки полосы докладывает о дороге к внешнему поставщику (%s) — у посадки "+
				"поставщика нет, и доклад о ней отвечал бы на вопрос, которого нет", key)
	}
}

// Законный близнец: та же строка докладывает о подписанте своей чеканки.
func TestLaneWiringCensusNamesTheOwnMintSigner(t *testing.T) {
	census := laneWiringCensus(config.LaneWiring{OwnMintSignerWired: true})
	found := false
	for i := 0; i+1 < len(census); i += 2 {
		if key, _ := census[i].(string); key == "own_mint_signer_wired" {
			found = census[i+1] == true
		}
	}
	require.True(t, found, "строка провязки полосы не докладывает о подписанте своей чеканки")
}

// signInLaneRootWithoutPostureKey — боевой корень с объявленным адресом полосы
// входа и БЕЗ ключа посадки. Собирается только из полей, переживающих снятие
// оси: иначе красное пробы было бы красным компиляции.
func signInLaneRootWithoutPostureKey() config.Config {
	var cfg config.Config
	cfg.AuthN.Mode = config.ModeProduction
	cfg.APIServer.LoginLaneEndpoint = "tcp://0.0.0.0:9100"
	return cfg
}

func TestProductionRootRequiresSignInLaneTLSWithoutAPostureKey(t *testing.T) {
	err := requireLoginLaneTLS(true, signInLaneRootWithoutPostureKey(), config.MTLSConfig{})
	require.Error(t, err, "боевой корень без ключа посадки не потребовал TLS у слушателя полосы входа — "+
		"полоса поднялась бы открытым текстом")
	require.True(t, strings.Contains(err.Error(), "KANAME_LOGINLANE_SERVER_MTLS_ENABLE"),
		"отказ не называет ручку TLS полосы входа: %v", err)
	require.NotContains(t, err.Error(), "identity-provider", "отказ называет снятый ключ посадки")
}

// Законный близнец: тот же корень с объявленным взаимным TLS проходит.
func TestProductionRootWithSignInLaneTLSPassesWithoutAPostureKey(t *testing.T) {
	require.NoError(t, requireLoginLaneTLS(true, signInLaneRootWithoutPostureKey(), mutualLane()))
}
