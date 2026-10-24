// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// registry_token_anonymous_render_test.go — ручка публичного принципала
// анонимного чтения (kaname#495) доходит от значений чарта до процесса, и это
// утверждается НАСТОЯЩИМ рендером и разбором настроек процесса.
//
// Что утверждается, отрицание — в паре с положительным близнецом:
//   - боевой профиль и базовые значения молчат о принципале: ключ в файл
//     настроек не попадает, а процесс читает пустое значение — анонимный поток
//     выключен;
//   - заданное значение отрендерено дословно и прочитано процессом в
//     `APIServer.RegistryToken.AnonymousClientID`; оно же доходит, когда больше
//     ничего о докерной полосе не объявлено (значение входит в условие блока);
//   - поток поднимается только со своими условиями (kaname#928, kaname#930):
//     темп на источник и доверенный пересыльщик доходят до процесса вместе с
//     принципалом, а слушатель выдачи запрашивает клиентский сертификат —
//     принципал без них чарт отвергает (anonymous_registry_lane_render_test.go).
//
// Пробы требуют helm и названы с приставки `TestProdProfile_Rendered`, поэтому
// их берёт полоса `deploy/render-guard.sh`; без helm — пропуск третьей
// категорией, не зелёное.
package deploy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// anonymousClientIDForRender — значение законной формы (слова через дефис).
const anonymousClientIDForRender = "registry-anonymous-reader"

// registryTokenSectionOf — раздел `api-server.registry-token` карты настроек;
// nil, если раздела нет.
func registryTokenSectionOf(t *testing.T, rendered string) map[string]any {
	t.Helper()
	tree := renderedConfigTree(t, rendered)
	api, _ := tree["api-server"].(map[string]any)
	require.NotNil(t, api, "раздел api-server не отрендерен — вход беспредметен")
	rt, _ := api["registry-token"].(map[string]any)
	return rt
}

// anonymousLaneConditionsForRender — темп и пересыльщик, без которых поток не
// собирается (kaname#928, kaname#930).
var anonymousLaneConditionsForRender = []string{
	"apiServer.registryToken.anonymousPerSourcePerSec=7",
	"apiServer.registryToken.anonymousForwarderSan=spiffe://kacho.cloud/ns/kacho/sa/kacho-registry",
}

// issuingListenerAskingForRender — слушатель выдачи под TLS, запрашивающий
// клиентский сертификат: накладка стенда его не объявляет.
var issuingListenerAskingForRender = []string{
	"env.KANAME_REGISTRYTOKEN_SERVER_MTLS_ENABLE=true",
	"env.KANAME_REGISTRYTOKEN_SERVER_MTLS_CLIENTAUTHMODE=optional-mutual",
	"env.KANAME_REGISTRYTOKEN_SERVER_MTLS_CLIENTCAFILES=/etc/kaname/tls/server/ca.crt",
	// Корень назван файлом тома сервера — без имени секрета тома нет.
	"tls.secretName=kaname-server-tls",
}

// loadedAnonymousClientID — значение, которое ПРОЦЕСС прочтёт из отрендеренного
// тела настроек с отрендеренным окружением.
func loadedAnonymousClientID(t *testing.T, rendered string) string {
	t.Helper()
	return loadedRegistryToken(t, rendered).AnonymousClientID
}

// loadedRegistryToken — раздел докерной полосы, как его прочтёт ПРОЦЕСС.
func loadedRegistryToken(t *testing.T, rendered string) config.RegistryTokenConfig {
	t.Helper()
	in := readRenderedInput(t, rendered)
	requireCleanEnv(t)
	for k, v := range in.Envs {
		t.Setenv(k, v)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(in.ConfigBody), 0o600))
	cfg, err := config.Load(path)
	require.NoErrorf(t, err, "отрендеренное тело настроек не разбирается:\n%s", in.ConfigBody)
	return cfg.APIServer.RegistryToken
}

func TestProdProfile_RenderedRegistryTokenAnonymousIsOffWhenSilent(t *testing.T) {
	t.Run("боевой профиль", func(t *testing.T) {
		out := renderStandaloneChart(t, []string{chartDefaultsFile, overlayWithout(t, nil)})
		rt := registryTokenSectionOf(t, out)
		require.NotNil(t, rt, "боевой профиль объявляет докерную полосу, а раздела нет — вход беспредметен")
		require.NotContains(t, rt, "anonymous-client-id",
			"молчащий профиль отрендерил ключ анонимного принципала — поток включён без объявления")
		require.Empty(t, loadedAnonymousClientID(t, out),
			"процесс прочёл непустой анонимный принципал при молчащем профиле — поток включён без объявления")
	})
	t.Run("базовые значения и накладка стенда", func(t *testing.T) {
		out := renderStandaloneChart(t, []string{chartDefaultsFile, "values.dev.yaml"})
		if rt := registryTokenSectionOf(t, out); rt != nil {
			require.NotContains(t, rt, "anonymous-client-id")
		}
		require.Empty(t, loadedAnonymousClientID(t, out))
	})
}

func TestProdProfile_RenderedRegistryTokenAnonymousReachesTheProcess(t *testing.T) {
	set := "apiServer.registryToken.anonymousClientId=" + anonymousClientIDForRender
	lane := append([]string{set}, anonymousLaneConditionsForRender...)

	t.Run("боевой профиль", func(t *testing.T) {
		out := renderStandaloneChart(t, []string{chartDefaultsFile, overlayWithout(t, nil)}, lane...)
		rt := registryTokenSectionOf(t, out)
		require.NotNil(t, rt, "раздел registry-token не отрендерен")
		require.Equal(t, anonymousClientIDForRender, rt["anonymous-client-id"])
		got := loadedRegistryToken(t, out)
		require.Equal(t, anonymousClientIDForRender, got.AnonymousClientID,
			"значение отрендерено, а процесс его не прочёл — ручка не доходит до сборки полосы")
		require.Equal(t, 7, got.AnonymousPerSourcePerSec, "темп потока не доходит до процесса")
		require.Equal(t, "spiffe://kacho.cloud/ns/kacho/sa/kacho-registry", got.AnonymousForwarderSAN,
			"пересыльщик потока не доходит до процесса")
	})
	t.Run("объявлено одно, без адресата и издателя", func(t *testing.T) {
		out := renderStandaloneChart(t, []string{chartDefaultsFile, "values.dev.yaml"},
			append(lane, issuingListenerAskingForRender...)...)
		rt := registryTokenSectionOf(t, out)
		require.NotNil(t, rt, "объявленный принципал пропал из файла настроек молча: значение не открывает блок")
		require.Equal(t, anonymousClientIDForRender, rt["anonymous-client-id"])
		require.Equal(t, anonymousClientIDForRender, loadedAnonymousClientID(t, out))
	})
}
