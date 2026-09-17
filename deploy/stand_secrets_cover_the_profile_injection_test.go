// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// stand_secrets_cover_the_profile_injection_test.go — способность меры упасть
// и смолчать доказывается ИНЪЕКЦИЕЙ по синтетике, а не прочтением.
//
// Синтетика, а не копия дерева: предмет меры — согласие ДВУХ текстов, и подать
// их можно значениями, не трогая ни скрипта, ни профиля. Прогонов четыре:
//
//	контроль          — перечни сходятся: мера молчит;
//	снятый ключ       — стенд не заводит ключ, который профиль объявляет:
//	                    краснеет, называя переменную, ключ и объект;
//	лишний ключ       — стенд заводит ключ сверх профиля: молчит (законный
//	                    близнец — лишний ключ пода не ломает);
//	чужой объект      — профиль адресует объект, который стенд не заводит:
//	                    в счёт не идёт (не предмет стенда), и обход об этом
//	                    сообщает числом.
//
// Отдельно — распознаватель исполняемой строки: ключ, названный ТОЛЬКО в
// комментарии скрипта, заведением не считается.
package deploy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func standSecretsFixture() ([]secretRef, map[string][]string) {
	refs := []secretRef{
		{Env: "KANAME_HOOK_TOKEN", Name: "kaname-authn", Key: "hook-shared-secret", Profile: "values.prod.yaml"},
		{Env: "KANAME_JWKS_ENC_KEY", Name: "kaname-authn", Key: "jwks-encryption-key-hex", Profile: "values.prod.yaml"},
		{Env: "KANAME_SECOND_FACTOR_ENC_KEY", Name: "kaname-authn", Key: "second-factor-encryption-key-hex", Profile: "values.prod.yaml"},
	}
	stand := map[string][]string{
		"kaname-authn": {"hook-shared-secret", "jwks-encryption-key-hex", "second-factor-encryption-key-hex"},
		"kaname-db":    {"password"},
	}
	return refs, stand
}

// TestInjection_StandSecretsControlIsSilent — КОНТРОЛЬ.
func TestInjection_StandSecretsControlIsSilent(t *testing.T) {
	refs, stand := standSecretsFixture()
	findings, judged := judgeStandSecretsCoverTheProfile(refs, stand)
	require.Equal(t, 3, judged)
	require.Empty(t, findings, "контроль красен — вердикты инъекций ниже недействительны")
}

// TestInjection_StandDroppingADeclaredKeyIsFound — ДЕФЕКТ: состояние дерева
// до починки, снятое живым подом.
func TestInjection_StandDroppingADeclaredKeyIsFound(t *testing.T) {
	refs, stand := standSecretsFixture()
	stand["kaname-authn"] = stand["kaname-authn"][:2]
	findings, judged := judgeStandSecretsCoverTheProfile(refs, stand)
	require.Equal(t, 3, judged)
	require.Len(t, findings, 1, "мера не нашла снятый ключ")
	require.Contains(t, findings[0], "KANAME_SECOND_FACTOR_ENC_KEY")
	require.Contains(t, findings[0], `"second-factor-encryption-key-hex"`)
	require.Contains(t, findings[0], "kaname-authn")
}

// TestInjection_StandExtraKeyIsLegal — ЗАКОННЫЙ БЛИЗНЕЦ.
func TestInjection_StandExtraKeyIsLegal(t *testing.T) {
	refs, stand := standSecretsFixture()
	stand["kaname-authn"] = append(stand["kaname-authn"], "provider-admin-token")
	findings, _ := judgeStandSecretsCoverTheProfile(refs, stand)
	require.Empty(t, findings, "лишний ключ стенда объявлен находкой — мера строже предмета: лишний ключ пода не ломает")
}

// TestInjection_StandForeignObjectIsNotJudged — объект не стенда в счёт не идёт.
func TestInjection_StandForeignObjectIsNotJudged(t *testing.T) {
	refs, stand := standSecretsFixture()
	refs = append(refs, secretRef{Env: "KANAME_HYDRA_ADMIN_TOKEN", Name: "operator-provider", Key: "token", Profile: "values.prod.yaml"})
	findings, judged := judgeStandSecretsCoverTheProfile(refs, stand)
	require.Equal(t, 3, judged, "чужой объект попал в счёт судимых")
	require.Empty(t, findings)
}

// TestInjection_StandScriptReaderSkipsComments — распознаватель читает
// ИСПОЛНЯЕМУЮ строку: ключ в комментарии заведением не является, а команда,
// разбитая продолжением `\`, собирается целиком.
func TestInjection_StandScriptReaderSkipsComments(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, filepath.Dir(standChartScriptRel))
	require.NoError(t, os.MkdirAll(dir, 0o750))
	script := "#!/usr/bin/env bash\n" +
		"# здесь ключ упомянут прозой: --from-literal=ghost-key=x в объекте \"$RELEASE-authn\"\n" +
		"kubectl create secret generic \"$RELEASE-authn\" \\\n" +
		"\t\t--from-literal=hook-shared-secret=\"$(openssl rand -hex 16)\" \\\n" +
		"\t\t--from-file=jwks-encryption-key-hex=\"$PKI/k\" >/dev/null\n" +
		"kubectl create secret generic \"$RELEASE-db\" --from-literal=password=\"$PG_PASSWORD\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, standChartScriptRel), []byte(script), 0o600))

	keys, lines := standSecretKeys(t, root)
	require.Equal(t, 7, lines, "шесть строк и хвостовой перевод строки")
	require.Equal(t, []string{"hook-shared-secret", "jwks-encryption-key-hex"}, keys["kaname-authn"],
		"продолжение команды не собрано либо ключ из комментария засчитан")
	require.Equal(t, []string{"password"}, keys["kaname-db"])
}
