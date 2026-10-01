// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// strict_config_test.go — СТРОГАЯ КОНФИГУРАЦИЯ: ключ файла, которого декодер не
// знает, и переменная пространства `__`, которой нет в выводимом множестве, —
// отказ старта, называющий предмет (замысел NTF-2 З5, приёмка NTF2-48).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ УТВЕРЖДАЕТСЯ
//
//	С1  ключ файла вне декодера — отказ с ПОЛНЫМ путём ключа, в трёх формах
//	    записи: лист под известной секцией, лист под известной вложенной
//	    секцией, неизвестная секция верхнего уровня; близнец — тот же файл
//	    без ключа — стартует, и известный ключ доезжает до поля;
//	С2  переменная `KANAME_…__…` вне выводимого множества — отказ с её
//	    именем; близнец — известная переменная той же формы — стартует и
//	    доезжает до поля;
//	С3  плоские имена (механизмы, которые этой проверкой НЕ судятся) и
//	    переменные служб кластера — старт: строгость сужена до `__`
//	    решением замысла, а не недоделкой;
//	С4  множество выведено из ключей декодера правилом EnvNameOfKey, и каждое
//	    имя, которое загрузка привязывает явно, в нём есть — иначе строгость
//	    отвергла бы документированную переменную.
//
// Производитель входа — сама Load: вердикт выносится по её исходу, а не по
// объявлению.
package config_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// strictTwinConfig — законный файл: близнец каждого отрицательного кейса С1.
// Кейс отличается от него РОВНО одним добавленным ключом.
const strictTwinConfig = `invite:
  ttl: 72h
authn:
  login:
    session-ttl: 12h
`

// С1.
func TestUnknownFileKeyRefusesStartNamingItsFullPath(t *testing.T) {
	cases := []struct {
		name, key, yaml string
	}{
		{
			name: "лист под известной секцией",
			key:  "invite.mail-rate-limit.max-per-hour",
			yaml: `invite:
  ttl: 72h
  mail-rate-limit:
    max-per-hour: 3
authn:
  login:
    session-ttl: 12h
`,
		},
		{
			name: "лист под известной вложенной секцией",
			key:  "authn.login.verification-resend-intervals",
			yaml: `invite:
  ttl: 72h
authn:
  login:
    session-ttl: 12h
    verification-resend-intervals: 60s
`,
		},
		{
			name: "неизвестная секция верхнего уровня",
			key:  "mail-node.relay",
			yaml: strictTwinConfig + `mail-node:
  relay: marker-ntf2-48.invalid:25
`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := config.Load(writeConfig(t, c.yaml))
			require.Error(t, err, "ключ %q декодер не знает — старт обязан быть отвергнут", c.key)
			require.Contains(t, err.Error(), "unknown configuration key `"+c.key+"`",
				"отказ обязан называть ПОЛНЫЙ путь ключа, а не родителя")
		})
	}

	t.Run("близнец: тот же файл без ключа стартует", func(t *testing.T) {
		cfg, err := config.Load(writeConfig(t, strictTwinConfig))
		require.NoError(t, err)
		require.Equal(t, 72*time.Hour, cfg.Invite.TTL,
			"близнец обязан ДОЕЗЖАТЬ: иначе он зеленеет и на файле, которого не прочли")
	})
}

// С2.
func TestUnknownNestedEnvRefusesStartNamingIt(t *testing.T) {
	for _, name := range []string{
		// опечатка в листе известной вложенной секции
		"KANAME_AUTHN__LOGIN__VERIFICATION_RESEND_INTERVALS",
		// неизвестная секция верхнего уровня
		"KANAME_MAIL_NODE__RELAY",
		// лист под известной секцией
		"KANAME_INVITE__MAIL_RATE_LIMIT__MAX_PER_HOUR",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "marker-ntf2-48")
			_, err := config.Load("")
			require.Error(t, err, "переменную %s ни один ключ декодера не производит", name)
			require.Contains(t, err.Error(), "unknown configuration variable `"+name+"`")
		})
	}

	t.Run("близнец: известная переменная той же формы стартует и доезжает", func(t *testing.T) {
		name := config.EnvNameOfKey("invite.ttl")
		t.Setenv(name, "48h")
		cfg, err := config.Load("")
		require.NoError(t, err)
		require.Equal(t, 48*time.Hour, cfg.Invite.TTL)
	})
}

// С3.
func TestFlatAndClusterNamesAreNotJudgedByTheNestedSpace(t *testing.T) {
	set := map[string]string{
		// переменные служб кластера: двойного подчёркивания кластер не производит
		"KANAME_INTERNAL_SERVICE_HOST":       "10.0.0.7",
		"KANAME_INTERNAL_SERVICE_PORT":       "9091",
		"KANAME_INTERNAL_PORT_9091_TCP":      "tcp://10.0.0.7:9091",
		"KANAME_INTERNAL_PORT_9091_TCP_ADDR": "10.0.0.7",
		// значения ключей `*-env` и прямые чтения окружения
		"KANAME_DB_PASSWORD":                 "pw",
		"KANAME_HYDRA_ISSUER":                "https://issuer.example",
		"KANAME_BOOTSTRAP_ROOT_EMAIL":        "root@example.org",
		"KANAME_RECONCILE_SWEEP_INTERVAL_MS": "30000",
		// чужая приставка с двойным подчёркиванием — не наше пространство
		"KANAMECTL__ENDPOINT": "x",
		"OTHER__THING":        "x",
	}
	// посадка транспорта (`envconfig`): имена выводятся из её же полей
	for _, n := range config.MTLSEnvNames() {
		set[n] = ""
	}
	for k, v := range set {
		t.Setenv(k, v)
	}
	// плоские псевдонимы загрузки — законными значениями их формы
	for k, v := range map[string]string{
		"KANAME_GRPC_PORT":     "19090",
		"KANAME_INTERNAL_PORT": "19091",
		"KANAME_DB_SSLMODE":    "require",
		"KANAME_AUTH_MODE":     "production",
	} {
		set[k] = v
		t.Setenv(k, v)
	}

	cfg, err := config.Load("")
	require.NoError(t, err, "строгость сужена до пространства `__`: плоские имена не судятся")
	require.Equal(t, "0.0.0.0:19090", cfg.APIServer.ListenAddress(),
		"плоский псевдоним обязан по-прежнему ДОЕЗЖАТЬ")
	t.Logf("перепись близнеца: имён окружения %d (из них посадки транспорта %d)",
		len(set), len(config.MTLSEnvNames()))
}

// С4.
func TestNestedEnvNamesAreDerivedFromTheDecoderKeys(t *testing.T) {
	names := config.NestedEnvNames()
	keys := config.DecoderKeys()
	require.NotEmpty(t, keys, "предпосылка: декодер знает хотя бы один ключ — пустой обход не вердикт")
	require.Len(t, names, len(keys), "имя на ключ — ровно одно")

	in := make(map[string]bool, len(names))
	for _, n := range names {
		in[n] = true
	}
	for _, k := range keys {
		require.True(t, in[config.EnvNameOfKey(k)], "имя ключа %q не выведено", k)
	}
	require.True(t, in["KANAME_REPOSITORY__POSTGRES__URL"],
		"предпосылка: документированная переменная адреса базы обязана быть в множестве")

	// Каждое имя, которое загрузка привязывает ЯВНО, обязано быть в множестве:
	// иначе строгость отвергла бы документированную переменную.
	bound := 0
	check := func(env string) {
		require.True(t, in[env], "явно привязанное имя %s вне множества", env)
		bound++
	}
	for _, k := range config.LoginLaneKnobs {
		check(k.Env)
	}
	for _, k := range config.RegistrationKnobs {
		check(k.Env)
	}
	for _, k := range config.AccessKeyKnobs {
		check(k.Env)
	}
	for _, k := range config.OwnCeilingKnobs {
		check(k.Env)
	}
	for _, k := range config.CeremonyLifespanKnobs {
		check(k.Env)
	}
	require.Positive(t, bound, "предпосылка: таблицы явных привязок не пусты")
	t.Logf("перепись: ключей декодера %d · имён пространства `__` %d · явно привязанных проверено %d",
		len(keys), len(names), bound)
}
