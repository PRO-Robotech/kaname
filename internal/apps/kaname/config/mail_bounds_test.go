// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_bounds_test.go — ТАБЛИЦА ГРАНИЦ почтовых ручек: флаг почты (NTF2-50),
// границы и наличие ручек Р8 (NTF2-71, варианты kaname), ключи файлов
// секретов (З18), привязка к окружению (З5), отсутствие умолчаний (З23).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ УТВЕРЖДАЕТСЯ
//
//	Б1  флаг не объявлен — отказ `notifications.enabled must be declared`;
//	    близнецы `true` и `false` — старт, значение доезжает до поля (NTF2-50);
//	Б2  варианты NTF2-71 kaname (а, б, в, л, м, н, о, п, у, ф, ч, ш) — отказ,
//	    называющий ключ и нарушенную границу; близнец — базовый профиль;
//	Б3  (т): у каждого из 32 ключей Р8 — вариант, где снят только он; отказ
//	    называет ключ и его отсутствие; число вариантов печатается;
//	Б4  отказ без каждого из ключей `authn.secrets.*` (З18);
//	Б5  ключ, заданный ТОЛЬКО переменной окружения, доезжает до поля — по
//	    ключу каждого вида таблицы и по каждой строке целиком (З5);
//	Б6  ни одна ручка таблицы не имеет умолчания в загрузчике (З23);
//	Б7  страж таблицы провязан в Validate: снятая ручка роняет общий старт.
//
// Базовый профиль выписан ЗДЕСЬ литералом из таблицы Р8 приёмки, а не собран
// из образцов таблицы границ: близнец, собранный из того же объявления, что
// судит страж, зеленел бы на любой его ошибке.
package config_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// baseMailProfile — ориентиры базового профиля (приёмка NTF-2 Р8) плюс флаг и
// два файла ключей.
const baseMailProfile = `notifications:
  enabled: true
authn:
  secrets:
    mail-window-key-file: /etc/kaname/secrets/mail-window.key
    device-label-key-file: /etc/kaname/secrets/device-label.key
  login:
    mail-window:
      recovery:
        first-pause: 60s
        second-pause: 5m
        per-hour: 3
        per-day: 5
        floor-interval: 6h
      verification:
        first-pause: 60s
        second-pause: 5m
        per-hour: 3
        per-day: 5
        floor-interval: 6h
      registration:
        first-pause: 60s
        second-pause: 5m
        per-hour: 3
        per-day: 5
        floor-interval: 6h
    recovery-code-ttl: 15m
    verification-code-ttl: 60m
    registration-code-ttl: 60m
    attempts:
      address-source-per-window: 5
      window: 15m
      address-failure-ceiling: 100
    mail-throttled-interval: 168h
    trusted-device:
      ttl: 2160h
      recovery-per-day: 2
invite:
  account-per-day: 200
  young-account-per-day: 50
  young-account-age: 720h
  pending-max: 200
  recipient-per-hour: 3
  recipient-per-day: 5
  recipient-per-day-all: 10
  ttl: 168h
`

// r8KanameKeys — 32 ключа kaname таблицы Р8 приёмки, раскрытием фигурных
// скобок. Выписаны здесь, а не взяты у таблицы границ: перепись (т) обязана
// сверять таблицу с приёмкой, а не саму с собой.
var r8KanameKeys = func() []string {
	var out []string
	for _, p := range []string{"recovery", "verification", "registration"} {
		for _, leaf := range []string{"first-pause", "second-pause", "per-hour", "per-day", "floor-interval"} {
			out = append(out, "authn.login.mail-window."+p+"."+leaf)
		}
	}
	out = append(out,
		"authn.login.recovery-code-ttl", "authn.login.verification-code-ttl", "authn.login.registration-code-ttl",
		"authn.login.attempts.address-source-per-window", "authn.login.attempts.window",
		"authn.login.attempts.address-failure-ceiling",
		"authn.login.mail-throttled-interval",
	)
	for _, leaf := range []string{"account-per-day", "young-account-per-day", "young-account-age", "pending-max",
		"recipient-per-hour", "recipient-per-day", "recipient-per-day-all", "ttl"} {
		out = append(out, "invite."+leaf)
	}
	out = append(out, "authn.login.trusted-device.ttl", "authn.login.trusted-device.recovery-per-day")
	return out
}()

var secretKeys = []string{"authn.secrets.mail-window-key-file", "authn.secrets.device-label-key-file"}

// profile — разобранный базовый профиль, который вариант меняет ровно в
// одном ключе.
type profile map[string]any

func baseProfile(t *testing.T) profile {
	t.Helper()
	var m map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(baseMailProfile), &m))
	return m
}

func (p profile) walk(t *testing.T, key string) (map[string]any, string) {
	t.Helper()
	segs := strings.Split(key, ".")
	cur := map[string]any(p)
	for _, s := range segs[:len(segs)-1] {
		next, ok := cur[s].(map[string]any)
		require.True(t, ok, "предпосылка: секция %q ключа %q есть в базовом профиле", s, key)
		cur = next
	}
	return cur, segs[len(segs)-1]
}

func (p profile) set(t *testing.T, key string, v any) profile {
	m, leaf := p.walk(t, key)
	_, had := m[leaf]
	require.True(t, had, "предпосылка: ключ %q есть в базовом профиле — вариант меняет, а не заводит", key)
	m[leaf] = v
	return p
}

func (p profile) drop(t *testing.T, key string) profile {
	m, leaf := p.walk(t, key)
	_, had := m[leaf]
	require.True(t, had, "предпосылка: ключ %q есть в базовом профиле — иначе снимать нечего", key)
	delete(m, leaf)
	return p
}

// guard — исход стража таблицы на профиле, поданном файлом через Load.
func (p profile) guard(t *testing.T) error {
	t.Helper()
	raw, err := yaml.Marshal(map[string]any(p))
	require.NoError(t, err)
	cfg, err := config.Load(writeConfig(t, string(raw)))
	require.NoError(t, err, "строгая загрузка обязана принять профиль: вариант судит страж, а не разбор")
	return cfg.ValidateMailBounds()
}

// Б1 — NTF2-50.
func TestNotificationsFlagMustBeDeclared(t *testing.T) {
	err := baseProfile(t).drop(t, "notifications.enabled").guard(t)
	require.Error(t, err, "флаг не объявлен — старт обязан быть отвергнут")
	require.Contains(t, err.Error(), "notifications.enabled must be declared")

	for _, v := range []bool{true, false} {
		t.Run(fmt.Sprintf("близнец %t", v), func(t *testing.T) {
			p := baseProfile(t).set(t, "notifications.enabled", v)
			require.NoError(t, p.guard(t))
			raw, _ := yaml.Marshal(map[string]any(p))
			cfg, err := config.Load(writeConfig(t, string(raw)))
			require.NoError(t, err)
			require.NotNil(t, cfg.Notifications.Enabled, "объявленное значение обязано доехать до поля")
			require.Equal(t, v, *cfg.Notifications.Enabled)
		})
	}
}

// Б2 — NTF2-71, варианты kaname.
func TestMailBoundsRefuseEachVariantNamingKeyAndBound(t *testing.T) {
	require.NoError(t, baseProfile(t).guard(t), "близнец: базовый профиль стартует")

	cases := []struct {
		variant string
		mut     func(t *testing.T, p profile) profile
		want    []string
	}{
		{"(а) снята recovery.per-day", func(t *testing.T, p profile) profile {
			return p.drop(t, "authn.login.mail-window.recovery.per-day")
		}, []string{"authn.login.mail-window.recovery.per-day must be declared"}},
		{"(б) per-hour больше per-day", func(t *testing.T, p profile) profile {
			return p.set(t, "authn.login.mail-window.recovery.per-hour", 6)
		}, []string{"authn.login.mail-window.recovery.per-hour", "authn.login.mail-window.recovery.per-day", "≤"}},
		{"(в) floor-interval = 30 мин", func(t *testing.T, p profile) profile {
			return p.set(t, "authn.login.mail-window.recovery.floor-interval", "30m")
		}, []string{"authn.login.mail-window.recovery.floor-interval", "30m0s", "1h0m0s"}},
		{"(л) registration.per-hour больше per-day", func(t *testing.T, p profile) profile {
			return p.set(t, "authn.login.mail-window.registration.per-hour", 7)
		}, []string{"authn.login.mail-window.registration.per-hour", "authn.login.mail-window.registration.per-day", "≤"}},
		{"(м) recovery-code-ttl меньше recovery.first-pause", func(t *testing.T, p profile) profile {
			p.set(t, "authn.login.recovery-code-ttl", "10m")
			return p.set(t, "authn.login.mail-window.recovery.first-pause", "15m")
		}, []string{"authn.login.mail-window.recovery.first-pause", "authn.login.recovery-code-ttl", "≤"}},
		{"(н) recipient-per-hour больше recipient-per-day", func(t *testing.T, p profile) profile {
			return p.set(t, "invite.recipient-per-hour", 6)
		}, []string{"invite.recipient-per-hour", "invite.recipient-per-day", "≤"}},
		{"(о) pending-max = 0", func(t *testing.T, p profile) profile {
			return p.set(t, "invite.pending-max", 0)
		}, []string{"invite.pending-max", "= 0", "1"}},
		{"(п) trusted-device.ttl = 0", func(t *testing.T, p profile) profile {
			return p.set(t, "authn.login.trusted-device.ttl", "0s")
		}, []string{"authn.login.trusted-device.ttl", "= 0s", "24h0m0s"}},
		{"(у) attempts.window = 2 ч", func(t *testing.T, p profile) profile {
			return p.set(t, "authn.login.attempts.window", "2h")
		}, []string{"authn.login.attempts.window", "2h0m0s", "1h0m0s"}},
		{"(ф) mail-throttled-interval = 12 ч", func(t *testing.T, p profile) profile {
			return p.set(t, "authn.login.mail-throttled-interval", "12h")
		}, []string{"authn.login.mail-throttled-interval", "12h0m0s", "24h0m0s"}},
		{"(ч) verification-code-ttl меньше verification.first-pause", func(t *testing.T, p profile) profile {
			p.set(t, "authn.login.verification-code-ttl", "10m")
			return p.set(t, "authn.login.mail-window.verification.first-pause", "15m")
		}, []string{"authn.login.mail-window.verification.first-pause", "authn.login.verification-code-ttl", "≤"}},
		{"(ш) registration-code-ttl меньше registration.first-pause", func(t *testing.T, p profile) profile {
			p.set(t, "authn.login.registration-code-ttl", "10m")
			return p.set(t, "authn.login.mail-window.registration.first-pause", "15m")
		}, []string{"authn.login.mail-window.registration.first-pause", "authn.login.registration-code-ttl", "≤"}},
	}
	for _, c := range cases {
		t.Run(c.variant, func(t *testing.T) {
			err := c.mut(t, baseProfile(t)).guard(t)
			require.Error(t, err, "вариант %s обязан отвергнуть старт", c.variant)
			for _, w := range c.want {
				require.Contains(t, err.Error(), w, "отказ обязан называть ключ и нарушенную границу")
			}
		})
	}
	t.Logf("перепись: вариантов NTF2-71 kaname %d", len(cases))
}

// Б3 — NTF2-71 (т).
func TestEveryR8KeyAbsenceRefusesStartNamingIt(t *testing.T) {
	require.Len(t, r8KanameKeys, 32, "предпосылка: таблица Р8 приёмки — 32 ключа kaname")

	inTable := map[string]config.MailBoundKind{}
	for _, b := range config.MailBounds {
		inTable[b.Key] = b.Kind
	}
	tableR8 := 0
	for _, b := range config.MailBounds {
		if b.Kind != config.MailBoundDeclared {
			tableR8++
		}
	}
	require.Equal(t, len(r8KanameKeys), tableR8,
		"строк таблицы границ вида «счёт» и «длительность» ровно столько, сколько ключей kaname в Р8")

	for _, key := range r8KanameKeys {
		t.Run(key, func(t *testing.T) {
			kind, ok := inTable[key]
			require.True(t, ok, "ключ Р8 %q не объявлен таблицей границ", key)
			require.NotEqual(t, config.MailBoundDeclared, kind)
			err := baseProfile(t).drop(t, key).guard(t)
			require.Error(t, err, "снят только %q — старт обязан быть отвергнут", key)
			require.Contains(t, err.Error(), key+" must be declared")
		})
	}
	t.Logf("перепись (т): вариантов %d — по одному на ключ kaname таблицы Р8", len(r8KanameKeys))
}

// Б4 — З18: отказ без каждого из двух ключей файлов секретов.
func TestSecretKeyFilesMustBeDeclared(t *testing.T) {
	for _, key := range secretKeys {
		t.Run(key, func(t *testing.T) {
			err := baseProfile(t).drop(t, key).guard(t)
			require.Error(t, err)
			require.Contains(t, err.Error(), key+" must be declared")
		})
	}
}

// Б5 — З5: ключ, заданный только переменной окружения, доезжает до поля.
func TestMailBoundKeySetOnlyByEnvReachesItsField(t *testing.T) {
	t.Run("по ключу каждого вида", func(t *testing.T) {
		t.Setenv(config.EnvNameOfKey("authn.login.mail-window.recovery.per-day"), "7")
		t.Setenv(config.EnvNameOfKey("authn.login.trusted-device.ttl"), "48h")
		t.Setenv(config.EnvNameOfKey("notifications.enabled"), "false")
		t.Setenv(config.EnvNameOfKey("authn.secrets.mail-window-key-file"), "/run/k_window")

		cfg, err := config.Load("")
		require.NoError(t, err)
		require.NotNil(t, cfg.AuthN.Login.MailWindow.Recovery.PerDay, "счёт")
		require.Equal(t, 7, *cfg.AuthN.Login.MailWindow.Recovery.PerDay)
		require.NotNil(t, cfg.AuthN.Login.TrustedDevice.TTL, "длительность")
		require.Equal(t, 48*time.Hour, *cfg.AuthN.Login.TrustedDevice.TTL)
		require.NotNil(t, cfg.Notifications.Enabled, "объявление-флаг")
		require.False(t, *cfg.Notifications.Enabled)
		require.Equal(t, "/run/k_window", cfg.AuthN.Secrets.MailWindowKeyFile, "объявление-путь")
	})

	t.Run("каждая строка таблицы", func(t *testing.T) {
		for _, b := range config.MailBounds {
			t.Setenv(config.EnvNameOfKey(b.Key), b.Sample)
		}
		cfg, err := config.Load("")
		require.NoError(t, err)
		require.NoError(t, cfg.ValidateMailBounds(),
			"все ручки поданы ТОЛЬКО окружением образцами таблицы — ни одна не обязана остаться незаданной")
		t.Logf("перепись: строк таблицы, поданных окружением, %d", len(config.MailBounds))
	})
}

// Б6 — З23: ни одной ручке таблицы загрузчик не подставляет значения.
func TestMailBoundsHaveNoLoaderDefault(t *testing.T) {
	cfg, err := config.Load("")
	require.NoError(t, err)
	err = cfg.ValidateMailBounds()
	require.Error(t, err, "пустой профиль обязан отказать: умолчаний у ручек нет")
	for _, b := range config.MailBounds {
		require.Contains(t, err.Error(), b.Key+" must be declared",
			"у ручки %q нашлось значение на пустом профиле — его подставил загрузчик", b.Key)
	}
	require.NotEmpty(t, config.MailBounds, "предпосылка: таблица не пуста")
}

// Б7 — страж таблицы провязан в общий страж старта.
func TestValidateRunsTheMailBoundsGuard(t *testing.T) {
	cfg := laneCfg(config.IdentityProviderOwn)
	require.NoError(t, cfg.Validate(), "близнец: годная фикстура стартует")
	cfg.Notifications.Enabled = nil
	err := cfg.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "notifications.enabled must be declared")
}
