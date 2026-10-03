// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// ceremony_lifespans_load_test.go — сроки церемонии через загрузчик
// (kaname#318; приёмка `ceremony-lifespans-are-declared-within-their-ceilings.md`,
// сценарии KN-CTTL-01…08).
//
// Путь — тот же, что у корня: `config.Load`, затем `Config.Validate()`. Профиль —
// боевой профиль посадки из образцов таблицы обязательных величин
// (`supplyProfile`, положительный контроль `TestRequiredSettings_TableCannotLie`);
// величина ручки подаётся переменной окружения поверх него с повтором загрузки
// (приёмка §0.7). Второго построителя профиля здесь нет.
//
// Диапазон `0 < срок ≤ потолок` утверждается с обеих сторон: снизу — отказ на
// нуле и отрицательном при приёме `1ns`, сверху — отказ на потолке плюс
// наносекунда при приёме потолка. Внутренняя величина (`30s`, `2h`) — то же
// число, с которым мир церемонии (`cmd/kaname`) собирает сборку мимо стража.

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

const (
	cttlCodeKey    = "authn.ceremony.code-ttl"
	cttlRefreshKey = "authn.ceremony.refresh-ttl"
	cttlCodeEnv    = "KANAME_AUTHN__CEREMONY__CODE_TTL"
	cttlRefreshEnv = "KANAME_AUTHN__CEREMONY__REFRESH_TTL"
)

// cttlOwn — боевой профиль, на котором судятся ручки сроков (имя историческое:
// прежде это была посадка `own`, kaname#363).
var cttlOwn = profilesUnderTest[0]

// ceremonyLifespanSettings — годные сроки церемонии для собранной руками
// боевой настройки: величины поставки, равные потолкам фундамента.
func ceremonyLifespanSettings() config.CeremonyConfig {
	return config.CeremonyConfig{CodeTTL: time.Minute, RefreshTTL: 168 * time.Hour}
}

// cttlProfile — полный профиль посадки без строки omit (пустое — полный), поверх
// которого поданы величины set; пустая величина снимает переменную. Окружение
// возвращается на выходе из пробы, а не из сборки: часть секретов профиля
// страж читает в момент `Validate`.
func cttlProfile(t *testing.T, lane profileUnderTest, omit string, set map[string]string) config.Config {
	t.Helper()
	saved := snapshotEnv()
	t.Cleanup(func() { restoreEnv(saved) })
	if _, err := supplyProfile(t.TempDir(), config.RequiredSettings, lane, omit); err != nil {
		t.Fatalf("НЕ-ВЫПОЛНИЛОСЬ(фикстура): профиль %s без %q не собран: %v", lane, omit, err)
	}
	for env, v := range set {
		var err error
		if v == "" {
			err = os.Unsetenv(env)
		} else {
			err = os.Setenv(env, v)
		}
		if err != nil {
			t.Fatalf("НЕ-ВЫПОЛНИЛОСЬ(фикстура): переменная %s: %v", env, err)
		}
	}
	// Строк с подачей файлом в таблице нет, поэтому повтор — без пути.
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("НЕ-ВЫПОЛНИЛОСЬ(фикстура): профиль %s не загрузился: %v", lane, err)
	}
	return cfg
}

// cttlRefusal — текст отказа стража; nil-отказ — пустая строка.
func cttlRefusal(cfg config.Config) string {
	if err := cfg.Validate(); err != nil {
		return err.Error()
	}
	return ""
}

func requireCttlRefusalNames(t *testing.T, id, got string, want ...string) {
	t.Helper()
	if got == "" {
		t.Fatalf("%s: Validate не отказал — старт прошёл бы без названного срока либо выше потолка", id)
	}
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("%s: текст отказа не называет %q:\n%s", id, w, got)
		}
	}
}

func requireCttlStartPasses(t *testing.T, id string, cfg config.Config) {
	t.Helper()
	if got := cttlRefusal(cfg); got != "" {
		t.Fatalf("%s: Validate отказал на допустимом входе:\n%s", id, got)
	}
}

// ── срок кода ────────────────────────────────────────────────────────────────

// KN-CTTL-01 — срок кода не назван, нулевой или отрицательный: отказ с именем
// ручки и переменной, и отказ именно о ней. Близнец — KN-CTTL-03.
func TestKNCTTL01_CodeTTLNotNamedRefusesTheStart(t *testing.T) {
	t.Run("01 строка снята", func(t *testing.T) {
		cfg := cttlProfile(t, cttlOwn, cttlCodeKey, nil)
		if cfg.AuthN.Ceremony.CodeTTL != 0 {
			t.Fatalf("KN-CTTL-01: загруженный срок кода %s — построение подставило величину", cfg.AuthN.Ceremony.CodeTTL)
		}
		got := cttlRefusal(cfg)
		requireCttlRefusalNames(t, "KN-CTTL-01", got, cttlCodeKey, cttlCodeEnv)
		if strings.Contains(got, cttlRefreshKey) {
			t.Errorf("KN-CTTL-01: отказ называет и %s, хотя снята только строка срока кода:\n%s", cttlRefreshKey, got)
		}
	})
	for _, tc := range []struct{ id, value string }{
		{"KN-CTTL-01/2", "0s"},
		{"KN-CTTL-01/3", "-1s"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			got := cttlRefusal(cttlProfile(t, cttlOwn, "", map[string]string{cttlCodeEnv: tc.value}))
			requireCttlRefusalNames(t, tc.id, got, cttlCodeKey, cttlCodeEnv)
			if strings.Contains(got, cttlRefreshKey) {
				t.Errorf("%s: отказ называет и %s:\n%s", tc.id, cttlRefreshKey, got)
			}
		})
	}
}

// KN-CTTL-02 — срок кода выше потолка на наносекунду: отказ называет ручку,
// поданную величину, константу фундамента и потолок.
func TestKNCTTL02_CodeTTLAboveTheCeilingRefusesTheStart(t *testing.T) {
	got := cttlRefusal(cttlProfile(t, cttlOwn, "", map[string]string{cttlCodeEnv: "60000000001ns"}))
	requireCttlRefusalNames(t, "KN-CTTL-02", got,
		cttlCodeKey, "1m0.000000001s", "tokenpolicy.MaxAuthorizationCodeTTL", "1m0s")
}

// KN-CTTL-03 — срок кода на потолке, на нижнем краю и внутри диапазона пускает
// старт и доезжает до настройки (близнец 01 и 02).
func TestKNCTTL03_CodeTTLWithinTheRangeReachesTheSetting(t *testing.T) {
	for _, tc := range []struct {
		id, value string
		want      time.Duration
	}{
		{"KN-CTTL-03", "60s", time.Minute},
		{"KN-CTTL-03/2", "1ns", time.Nanosecond},
		{"KN-CTTL-03/3", "30s", 30 * time.Second},
	} {
		t.Run(tc.id, func(t *testing.T) {
			cfg := cttlProfile(t, cttlOwn, "", map[string]string{cttlCodeEnv: tc.value})
			requireCttlStartPasses(t, tc.id, cfg)
			if cfg.AuthN.Ceremony.CodeTTL != tc.want {
				t.Fatalf("%s: загруженный срок кода %s, подано %s", tc.id, cfg.AuthN.Ceremony.CodeTTL, tc.value)
			}
		})
	}
}

// ── срок семейства ───────────────────────────────────────────────────────────

// KN-CTTL-04 — срок семейства не назван, нулевой или отрицательный: отказ с
// именем ручки. Близнец — KN-CTTL-06.
func TestKNCTTL04_RefreshTTLNotNamedRefusesTheStart(t *testing.T) {
	t.Run("04 строка снята", func(t *testing.T) {
		cfg := cttlProfile(t, cttlOwn, cttlRefreshKey, nil)
		if cfg.AuthN.Ceremony.RefreshTTL != 0 {
			t.Fatalf("KN-CTTL-04: загруженный срок семейства %s — построение подставило величину", cfg.AuthN.Ceremony.RefreshTTL)
		}
		got := cttlRefusal(cfg)
		requireCttlRefusalNames(t, "KN-CTTL-04", got, cttlRefreshKey, cttlRefreshEnv)
		if strings.Contains(got, cttlCodeKey) {
			t.Errorf("KN-CTTL-04: отказ называет и %s, хотя снята только строка срока семейства:\n%s", cttlCodeKey, got)
		}
	})
	for _, tc := range []struct{ id, value string }{
		{"KN-CTTL-04/2", "0s"},
		{"KN-CTTL-04/3", "-1s"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			got := cttlRefusal(cttlProfile(t, cttlOwn, "", map[string]string{cttlRefreshEnv: tc.value}))
			requireCttlRefusalNames(t, tc.id, got, cttlRefreshKey, cttlRefreshEnv)
			if strings.Contains(got, cttlCodeKey) {
				t.Errorf("%s: отказ называет и %s:\n%s", tc.id, cttlCodeKey, got)
			}
		})
	}
}

// KN-CTTL-05 — срок семейства выше потолка на наносекунду.
func TestKNCTTL05_RefreshTTLAboveTheCeilingRefusesTheStart(t *testing.T) {
	got := cttlRefusal(cttlProfile(t, cttlOwn, "", map[string]string{cttlRefreshEnv: "604800000000001ns"}))
	requireCttlRefusalNames(t, "KN-CTTL-05", got,
		cttlRefreshKey, "168h0m0.000000001s", "tokenpolicy.MaxRefreshTokenFamilyTTL", "168h0m0s")
}

// KN-CTTL-06 — срок семейства на потолке, на нижнем краю и внутри диапазона
// пускает старт и доезжает до настройки (близнец 04 и 05). 06/2 утверждает и то,
// что соотношения с соседними сроками страж не судит: 1ns короче срока кода и
// срока токена доступа профиля.
func TestKNCTTL06_RefreshTTLWithinTheRangeReachesTheSetting(t *testing.T) {
	for _, tc := range []struct {
		id, value string
		want      time.Duration
	}{
		{"KN-CTTL-06", "168h", 168 * time.Hour},
		{"KN-CTTL-06/2", "1ns", time.Nanosecond},
		{"KN-CTTL-06/3", "2h", 2 * time.Hour},
	} {
		t.Run(tc.id, func(t *testing.T) {
			cfg := cttlProfile(t, cttlOwn, "", map[string]string{cttlRefreshEnv: tc.value})
			requireCttlStartPasses(t, tc.id, cfg)
			if cfg.AuthN.Ceremony.RefreshTTL != tc.want {
				t.Fatalf("%s: загруженный срок семейства %s, подано %s", tc.id, cfg.AuthN.Ceremony.RefreshTTL, tc.value)
			}
		})
	}
}

// ── обе ручки и посадка ──────────────────────────────────────────────────────

// KN-CTTL-07 — обе ручки не названы: один отказ называет обе.
func TestKNCTTL07_BothLifespansMissingAreNamedInOneRefusal(t *testing.T) {
	got := cttlRefusal(cttlProfile(t, cttlOwn, cttlCodeKey, map[string]string{cttlRefreshEnv: ""}))
	requireCttlRefusalNames(t, "KN-CTTL-07", got, cttlCodeKey, cttlRefreshKey)
}

// KN-CTTL-08 — сроки судятся на боевом старте: обе не названы · срок кода выше
// потолка — отказ.
//
// Прежде у сценария были две половины `external` — «строки полосы external
// ручек сроков не требуют и не судят», — и половины `own` были им близнецами.
// Посадка `external` снята вместе с ключом посадки (kaname#363): её строк в
// таблице нет, и половин, которые их судили, — тоже. Сценарий приёмки
// возвращается в приёмку (его «Дано» больше не выполнимо); здесь остаются
// половины, чей предмет жив, и близнец у них свой — годный профиль
// (KN-CTTL-02/05 выше).
func TestKNCTTL08_LifespansAreJudgedOnTheProductionStart(t *testing.T) {
	t.Run("08/3 обе не названы", func(t *testing.T) {
		got := cttlRefusal(cttlProfile(t, cttlOwn, cttlCodeKey, map[string]string{cttlRefreshEnv: ""}))
		requireCttlRefusalNames(t, "KN-CTTL-08/3", got, cttlCodeKey, cttlRefreshKey)
	})
	t.Run("08/4 срок кода выше потолка", func(t *testing.T) {
		got := cttlRefusal(cttlProfile(t, cttlOwn, "", map[string]string{cttlCodeEnv: "2m"}))
		requireCttlRefusalNames(t, "KN-CTTL-08/4", got, cttlCodeKey, "1m0s")
	})
}
