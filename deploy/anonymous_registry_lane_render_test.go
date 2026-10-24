// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package deploy_test

// anonymous_registry_lane_render_test.go — анонимный поток докерной полосы
// рендерится только целиком (kaname#928, kaname#930).
//
// Процесс не стартует, если при объявленном принципале потока не объявлены темп
// на источник и доверенный пересыльщик, а слушатель выдачи не запрашивает
// клиентский сертификат. До этой правки чарт выводил только принципал: любой
// профиль, включавший поток, давал настройку, на которой процесс отказывался
// стартовать.
//
// Что утверждается, каждое отрицание — в паре с положительным контролем:
//   - поток включён на боевой цепочке — в карте все три ключа с объявленными
//     значениями;
//   - поток выключен — ни одного из трёх, в том числе когда темп и пересыльщик
//     объявлены без принципала;
//   - поток включён без любой из своих условий (темп, пересыльщик, TLS
//     слушателя, режим `optional-mutual`, корень клиентских сертификатов) —
//     отказ рендера, называющий недостающее;
//   - ручка потока, поданная окружением пода, — отказ: переменная перекрыла бы
//     файл настроек и обошла страж.
//
// Вход собирается настоящим `helm template`; без helm проба — третья категория,
// а на объявленной полосе рендера (deploy/render-guard.sh) — отказ.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	anonProdChain = []string{"values.yaml", "values.prod.yaml"}
	anonLaneOn    = []string{
		"apiServer.registryToken.anonymousClientId=registry-anonymous",
		"apiServer.registryToken.anonymousPerSourcePerSec=7",
		"apiServer.registryToken.anonymousForwarderSan=spiffe://kacho.cloud/ns/kacho/sa/kacho-registry",
	}
	anonLaneKeys = []string{"anonymous-client-id", "anonymous-per-source-per-sec", "anonymous-forwarder-san"}
)

// registryTokenSection — раздел api-server.registry-token карты настроек.
func registryTokenSection(t *testing.T, out string) map[string]any {
	t.Helper()
	tree := renderedConfigTree(t, out)
	api, _ := tree["api-server"].(map[string]any)
	rt, _ := api["registry-token"].(map[string]any)
	return rt
}

func TestAnonymousRegistryLane_OnRendersAllThreeKeys(t *testing.T) {
	out, err := renderChartAtAllowingFailure(t, ".", anonProdChain, anonLaneOn...)
	require.NoErrorf(t, err, "законный включённый поток отвергнут рендером:\n%s", out)
	rt := registryTokenSection(t, out)
	require.NotNil(t, rt, "раздел api-server.registry-token не отрендерен")
	require.Equal(t, "registry-anonymous", rt["anonymous-client-id"])
	require.EqualValues(t, 7, rt["anonymous-per-source-per-sec"])
	require.Equal(t, "spiffe://kacho.cloud/ns/kacho/sa/kacho-registry", rt["anonymous-forwarder-san"])
}

func TestAnonymousRegistryLane_OffRendersNone(t *testing.T) {
	for _, tc := range []struct {
		name string
		sets []string
	}{
		{"профиль молчит", nil},
		{"темп и пересыльщик без принципала", anonLaneOn[1:]},
	} {
		out, err := renderChartAtAllowingFailure(t, ".", anonProdChain, tc.sets...)
		require.NoErrorf(t, err, "%s: выключенный поток отвергнут рендером:\n%s", tc.name, out)
		rt := registryTokenSection(t, out)
		for _, k := range anonLaneKeys {
			_, has := rt[k]
			require.Falsef(t, has, "%s: поток выключен, а ключ %s отрендерен", tc.name, k)
		}
	}
}

func TestAnonymousRegistryLane_RefusesWithoutItsConditions(t *testing.T) {
	for _, tc := range []struct {
		name  string
		drop  int // индекс снятой ручки потока, -1 — ни одной
		extra []string
		says  string
	}{
		{"темп не объявлен", 1, nil, "apiServer.registryToken.anonymousPerSourcePerSec"},
		{"пересыльщик не объявлен", 2, nil, "apiServer.registryToken.anonymousForwarderSan"},
		{"слушатель без TLS", -1, []string{"env.KANAME_REGISTRYTOKEN_SERVER_MTLS_ENABLE=false"},
			"KANAME_REGISTRYTOKEN_SERVER_MTLS_ENABLE"},
		{"слушатель не спрашивает сертификат", -1,
			[]string{"env.KANAME_REGISTRYTOKEN_SERVER_MTLS_CLIENTAUTHMODE=server-tls-only"},
			"KANAME_REGISTRYTOKEN_SERVER_MTLS_CLIENTAUTHMODE=optional-mutual"},
		{"слушатель требует сертификат у всех", -1,
			[]string{"env.KANAME_REGISTRYTOKEN_SERVER_MTLS_CLIENTAUTHMODE=mutual"},
			"KANAME_REGISTRYTOKEN_SERVER_MTLS_CLIENTAUTHMODE=optional-mutual"},
		{"корень клиентских сертификатов пуст", -1,
			[]string{"env.KANAME_REGISTRYTOKEN_SERVER_MTLS_CLIENTCAFILES="},
			"KANAME_REGISTRYTOKEN_SERVER_MTLS_CLIENTCAFILES"},
		{"ручка потока окружением пода", -1,
			[]string{"env.KANAME_API_SERVER__REGISTRY_TOKEN__ANONYMOUS_FORWARDER_SAN=spiffe://kacho.cloud/ns/x/sa/y"},
			"apiServer.registryToken.anonymousForwarderSan"},
	} {
		var sets []string
		for i, s := range anonLaneOn {
			if i != tc.drop {
				sets = append(sets, s)
			}
		}
		sets = append(sets, tc.extra...)
		out, err := renderChartAtAllowingFailure(t, ".", anonProdChain, sets...)
		require.Errorf(t, err, "%s: рендер принял поток без его условия:\n%s", tc.name, out)
		require.Containsf(t, out, tc.says, "%s: отказ не называет недостающее:\n%s", tc.name, out)
	}
}

// TestAnonymousRegistryLane_ListenerOffIsNotJudged — адрес слушателя объявлен
// пустым: полосы нет, и поток не поднят — тот же предикат, что у процесса.
func TestAnonymousRegistryLane_ListenerOffIsNotJudged(t *testing.T) {
	out, err := renderChartAtAllowingFailure(t, ".", anonProdChain,
		"apiServer.registryToken.anonymousClientId=registry-anonymous",
		"apiServer.registryToken.endpoint=")
	require.NoErrorf(t, err, "слушатель выключен, а условия потока судятся:\n%s", out)
}
