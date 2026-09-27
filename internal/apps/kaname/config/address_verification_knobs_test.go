// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// address_verification_knobs_test.go — EV-90 приёмки
// `access-beyond-login-needs-a-verified-address.md` (kaname#456, Р9): пять
// ручек глагола подтверждения без умолчания; незаданная — отказ старта с именем
// ключа и переменной; опись обязательных настроек несёт все пять с величинами
// профиля продукта.
//
// Ручки находятся по ключу настройки (`mapstructure`), а не по имени поля Go:
// предмет пробы — объявленный ключ, и его отсутствие есть «ручки нет».
package config_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// verificationKnobs — ключи и переменные Р9, дословно, с величиной профиля.
var verificationKnobs = []struct{ short, env, sample string }{
	{"verification-code-ttl", "KANAME_AUTHN__LOGIN__VERIFICATION_CODE_TTL", "30m"},
	{"verification-code-attempts", "KANAME_AUTHN__LOGIN__VERIFICATION_CODE_ATTEMPTS", "5"},
	{"verification-resend-interval", "KANAME_AUTHN__LOGIN__VERIFICATION_RESEND_INTERVAL", "60s"},
	{"verification-resend-limit", "KANAME_AUTHN__LOGIN__VERIFICATION_RESEND_LIMIT", "5"},
	{"verification-resend-window", "KANAME_AUTHN__LOGIN__VERIFICATION_RESEND_WINDOW", "24h"},
}

// loginFieldByKey — поле настройки полосы входа по ключу `mapstructure`.
func loginFieldByKey(v reflect.Value, key string) (reflect.Value, bool) {
	tp := v.Type()
	for i := 0; i < tp.NumField(); i++ {
		if strings.Split(tp.Field(i).Tag.Get("mapstructure"), ",")[0] == key {
			return v.Field(i), true
		}
	}
	return reflect.Value{}, false
}

// TestEV90_FiveKnobsWithoutDefaults — EV-90.
func TestEV90_FiveKnobsWithoutDefaults(t *testing.T) {
	for _, k := range verificationKnobs {
		t.Run(k.short, func(t *testing.T) {
			cfg := laneCfg(config.IdentityProviderOwn)
			f, ok := loginFieldByKey(reflect.ValueOf(&cfg.AuthN.Login).Elem(), k.short)
			if !ok {
				t.Fatalf("ЧЕСТНЫЙ-КРАСНЫЙ EV-90 (а): ручки authn.login.%s в настройке нет — старт проходит без неё", k.short)
			}
			require.NoError(t, cfg.Validate(), "EV-90 (б): все пять заданы — старт")
			f.Set(reflect.Zero(f.Type()))
			err := cfg.Validate()
			require.Error(t, err, "EV-90 (а): незаданная ручка — отказ старта")
			require.Contains(t, err.Error(), "authn.login."+k.short, "EV-90 (а): отказ называет ключ")
			require.Contains(t, err.Error(), k.env, "EV-90 (а): отказ называет переменную")
		})
	}
	t.Run("опись обязательных настроек", func(t *testing.T) {
		for _, k := range verificationKnobs {
			var found bool
			for _, s := range config.RequiredSettings {
				if s.Key == "authn.login."+k.short {
					found = true
					require.Equal(t, k.env, s.Env, "опись: переменная %s", k.short)
					require.Equal(t, k.sample, s.Sample, "опись: величина профиля продукта %s (Р9)", k.short)
				}
			}
			require.Truef(t, found, "EV-90: опись обязательных настроек не несёт authn.login.%s", k.short)
		}
	})
}
