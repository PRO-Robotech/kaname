// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// login_lane_address_install_test.go — адрес полосы входа, которого требует
// страж посадки, назван оператору в INSTALL.md (kaname#258, п.4).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// [requireLoginLaneTLS] отказывает боевому старту без адреса полосы входа, и
// умолчания у адреса нет. Таблица обязательных величин INSTALL §3 порождается из
// стража НАСТРОЙКИ и этого стража не видит BY CONSTRUCTION: он — стадия
// «посадка» (INSTALL §5). Значит, строка об адресе живёт ВНЕ порождённого блока,
// иначе оператор узнаёт о ручке отказом на стенде.
//
// Имя ключа выводится из имени переменной, которое печатает отказ стража
// ([knobLoginLane]), тем же правилом, каким его выводит INSTALL §3 (точка — два
// подчёркивания, дефис — одно): переименование ручки роняет эту пробу, а не
// оставляет документ называть прежнее имя.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	installGeneratedBegin = "<!-- ПОРОЖДЕНО: обязательные величины — начало -->"
	installGeneratedEnd   = "<!-- ПОРОЖДЕНО: обязательные величины — конец -->"
)

// keyOfEnv — путь ключа настройки из имени переменной: префикс службы снят,
// `__` — точка, `_` — дефис, регистр нижний.
func keyOfEnv(env string) string {
	rest := strings.ToLower(strings.TrimPrefix(env, "KANAME_"))
	parts := strings.Split(rest, "__")
	for i, p := range parts {
		parts[i] = strings.ReplaceAll(p, "_", "-")
	}
	return strings.Join(parts, ".")
}

// installNamesKnob — суждение над ПРОИЗВОЛЬНЫМ текстом: есть ли ВНЕ порождённого
// блока строка, называющая и ключ, и переменную. Возвращает число строк вне
// блока (перепись) и число строк, назвавших ручку.
func installNamesKnob(text, key, env string) (outside, naming int) {
	in := false
	for _, line := range strings.Split(text, "\n") {
		switch strings.TrimSpace(line) {
		case installGeneratedBegin:
			in = true
			continue
		case installGeneratedEnd:
			in = false
			continue
		}
		if in {
			continue
		}
		outside++
		if strings.Contains(line, key) && strings.Contains(line, env) {
			naming++
		}
	}
	return outside, naming
}

func TestInstallNamesTheLoginLaneAddressTheLandingGuardDemands(t *testing.T) {
	key := keyOfEnv(knobLoginLane)
	require.Equal(t, "api-server.login-lane-endpoint", key,
		"вывод ключа из переменной разошёлся с правилом INSTALL §3 — проба судила бы не ту ручку")

	path := filepath.Join("..", "..", "INSTALL.md")
	raw, err := os.ReadFile(path) // #nosec G304 -- путь из корня службы
	require.NoErrorf(t, err, "INSTALL.md не читается: %s", path)

	outside, naming := installNamesKnob(string(raw), key, knobLoginLane)
	t.Logf("ПЕРЕПИСЬ: строк INSTALL вне порождённого блока %d · строк, назвавших %s и %s, %d",
		outside, key, knobLoginLane, naming)
	require.NotZero(t, outside, "вне порождённого блока НЕТ строк — судить нечего, это не зелёное")
	require.NotZerof(t, naming, "INSTALL.md не называет ВНЕ порождённого блока адрес полосы входа "+
		"(%s, переменная %s), а страж посадки без него отказывает боевому старту: оператор узнает о "+
		"ручке отказом на стенде", key, knobLoginLane)
}

// --- инъекция: суждение способно упасть, законный близнец молчит ---

func TestInstallNamesKnobInjection(t *testing.T) {
	key, env := "api-server.login-lane-endpoint", "KANAME_API_SERVER__LOGIN_LANE_ENDPOINT"
	row := "| `" + key + "` | переменная `" + env + "` | боевой режим | … |"
	for name, tc := range map[string]struct {
		text string
		want int
	}{
		"строка вне блока — найдена":      {text: "# §5\n" + row + "\n", want: 1},
		"строка внутри блока — не в счёт": {text: installGeneratedBegin + "\n" + row + "\n" + installGeneratedEnd + "\n", want: 0},
		"только ключ без переменной":      {text: "`" + key + "`\n", want: 0},
		"только переменная без ключа":     {text: "`" + env + "`\n", want: 0},
		"ни строки": {text: "# §5\n", want: 0},
		"после блока — снова в счёт": {text: installGeneratedBegin + "\n" + installGeneratedEnd + "\n" + row + "\n", want: 1},
	} {
		t.Run(name, func(t *testing.T) {
			_, naming := installNamesKnob(tc.text, key, env)
			require.Equal(t, tc.want, naming)
		})
	}
}
