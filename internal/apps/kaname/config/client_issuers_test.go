// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/testsupport/moduleroster"
)

// fullyPopulatedProduction — боевой профиль, проходящий стража целиком.
func fullyPopulatedProduction() config.Config {
	cfg := goodEndpoints(config.ModeProduction, "require")
	cfg.AuthN.JWKSEncryptionKeyHex = strings.Repeat("ab", 32)
	return cfg
}

// TestValidate_Production_RefusesAnIdentityNotBoundToItsIssuer — kaname#988:
// в боевом режиме личность без центра — отказ, называющий пару; та же личность,
// привязанная к объявленному центру, — проход.
func TestValidate_Production_RefusesAnIdentityNotBoundToItsIssuer(t *testing.T) {
	cfg := fullyPopulatedProduction()
	require.NoError(t, cfg.Validate(), "близнец: привязанная личность и объявленный центр")

	cfg.AuthN.ModuleIdentities = []string{"kacho/kacho-api-gateway=edge"}
	err := cfg.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "kacho/kacho-api-gateway")
	require.Contains(t, err.Error(), "name no issuer")
}

// TestValidate_RefusesAnIdentityNamingAnUndeclaredIssuer — центр, которого
// установка не объявила, — отказ в любом режиме; файл центра стражем настройки
// не читается (его читает корень при подъёме).
func TestValidate_RefusesAnIdentityNamingAnUndeclaredIssuer(t *testing.T) {
	for _, mode := range []config.Mode{config.ModeProduction, config.ModeDev} {
		cfg := fullyPopulatedProduction()
		cfg.AuthN.Mode = mode
		cfg.AuthN.ClientIssuers = []string{"edge=/nowhere/edge.pem"}
		err := cfg.Validate()
		require.Error(t, err, "режим %s", mode)
		require.Contains(t, err.Error(), `names the issuer "internal"`)
		require.Contains(t, err.Error(), "authn.client-issuers")
	}
}

// TestLoadModuleRoster_ReadsTheIssuerAndRefusesAnUnreadableOne — корень
// читает центр из файла; нечитаемый либо пустой файл — ошибка подъёма, а не
// перечень, признающий меньше объявленного.
func TestLoadModuleRoster_ReadsTheIssuerAndRefusesAnUnreadableOne(t *testing.T) {
	ca := moduleroster.NewCA(t, "internal-ca")
	dir := t.TempDir()
	good := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(good, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert().Raw}), 0o600))
	empty := filepath.Join(dir, "empty.pem")
	require.NoError(t, os.WriteFile(empty, []byte("no certificate here\n"), 0o600))

	var a config.AuthNConfig
	a.ServiceNameFormRaw = moduleroster.NameFormRaw
	a.ModuleIdentities = []string{"kacho/kacho-vpc=module-writer@internal"}

	a.ClientIssuers = []string{"internal=" + good}
	r, err := a.LoadModuleRoster()
	require.NoError(t, err)
	_, ok := r.FromContext(ca.PeerContext(t, moduleroster.DeclaredVPC))
	require.True(t, ok, "лист прочитанного центра не признан")

	for name, path := range map[string]string{"файла нет": filepath.Join(dir, "absent.pem"), "сертификата нет": empty} {
		a.ClientIssuers = []string{"internal=" + path}
		r, err := a.LoadModuleRoster()
		require.Error(t, err, name)
		require.Contains(t, err.Error(), `client issuer "internal"`, name)
		require.False(t, r.IsDeclared(), "%s: перечень рядом с ошибкой не пуст", name)
	}
}
