// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// dsn_one_form_test.go — у точки наката то же правило адреса базы, что у
// службы: адрес, объявленный больше чем одним источником, — отказ (#532).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО БЫЛО И ЧЕМ ЭТО СТОИЛО
//
// Служба отказывает в старте, когда адрес базы задан обеими своими формами —
// строкой целиком и по полям (`config.refuseAmbiguousDSN`): молчаливое
// старшинство в любую сторону выбрасывает одну из настроек оператора. Точка
// наката читала адрес иначе — `--dsn` > ENV > конфигурация службы — и старшинство
// выбирала САМА. Заданная переменная наката молча побеждала конфигурацию службы:
// схему накатывали на одну базу, служба читала другую, под при этом был Ready.
// Это тот же класс «принято-и-проигнорировано», ради которого у службы отказ.
//
// Точка наката исполняется init-контейнером ТОГО ЖЕ пода, что служба, и читает
// ту же конфигурацию, — значит и правило у неё то же: источников у неё три,
// объявленным может быть ровно один.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ОТРИЦАНИЯ ИДУТ В ПАРЕ С БЛИЗНЕЦАМИ
//
// Каждый отказ ниже отличается от своего положительного близнеца РОВНО ОДНИМ
// фактом — вторым объявленным источником. Без близнецов проба зеленела бы на
// точке наката, отвергающей любой адрес из этого источника.
package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// addressEnv — все переменные, которыми адрес базы доезжает до точки наката:
// две свои (нейтральное и прежнее написание) и формы конфигурации службы.
var addressEnv = []string{
	"MIGRATOR_DSN",
	"KACHO_MIGRATOR_DSN",
	"KANAME_CONFIG_PATH",
	"KANAME_REPOSITORY__POSTGRES__URL",
	"KANAME_DB_HOST",
	"KANAME_DB_PORT",
	"KANAME_DB_USER",
	"KANAME_DB_NAME",
}

// clearAddressEnv снимает унаследованные формы адреса: проба судит ровно те
// источники, которые объявила сама. `t.Setenv` регистрирует возврат прежнего
// значения, `Unsetenv` делает переменную НЕЗАДАННОЙ — у расщеплённых ручек
// службы заданная пустой считается заданной.
func clearAddressEnv(t *testing.T) {
	t.Helper()
	for _, name := range addressEnv {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatalf("unset %s: %v", name, err)
		}
	}
}

// serviceConfigFile — файл конфигурации службы, объявляющий адрес базы.
func serviceConfigFile(t *testing.T, url string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := "repository:\n  postgres:\n    url: \"" + url + "\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

const (
	addrA = "postgres://iam@pg-a:5432/kaname"
	addrB = "postgres://iam@pg-b:5432/kaname"
)

// refusalCase — два объявленных источника и имена, которые отказ обязан назвать.
type refusalCase struct {
	name  string
	flag  string
	env   map[string]string
	file  bool
	names []string
}

func refusalCases() []refusalCase {
	return []refusalCase{
		{
			name:  "flag and neutral env",
			flag:  addrA,
			env:   map[string]string{"MIGRATOR_DSN": addrB},
			names: []string{"--dsn", "MIGRATOR_DSN"},
		},
		{
			// Ровно случай задачи: переменная наката прежним написанием молча
			// перебивала конфигурацию службы.
			name:  "legacy env and service url env",
			env:   map[string]string{"KACHO_MIGRATOR_DSN": addrA, "KANAME_REPOSITORY__POSTGRES__URL": addrB},
			names: []string{"KACHO_MIGRATOR_DSN", "KANAME_REPOSITORY__POSTGRES__URL"},
		},
		{
			name:  "neutral env and service config file",
			env:   map[string]string{"MIGRATOR_DSN": addrA},
			file:  true,
			names: []string{"MIGRATOR_DSN", "repository.postgres.url"},
		},
		{
			name:  "flag and service split fields",
			flag:  addrA,
			env:   map[string]string{"KANAME_DB_HOST": "pg-b", "KANAME_DB_NAME": "kaname"},
			names: []string{"--dsn", "KANAME_DB_HOST", "KANAME_DB_NAME"},
		},
	}
}

func applyCase(t *testing.T, flag string, env map[string]string, file bool) *rootOptions {
	t.Helper()
	clearAddressEnv(t)
	for k, v := range env {
		t.Setenv(k, v)
	}
	if file {
		t.Setenv("KANAME_CONFIG_PATH", serviceConfigFile(t, addrB))
	}
	return &rootOptions{dialect: defaultDialect, dsn: flag}
}

// TestBuildRunner_RefusesAnAddressDeclaredTwice — отрицание: два объявленных
// источника — отказ, и он называет КАЖДЫЙ из них, а не первый попавшийся.
func TestBuildRunner_RefusesAnAddressDeclaredTwice(t *testing.T) {
	for _, tc := range refusalCases() {
		t.Run(tc.name, func(t *testing.T) {
			opts := applyCase(t, tc.flag, tc.env, tc.file)

			_, err := buildRunner(opts, fstest.MapFS{})
			if err == nil {
				t.Fatalf("buildRunner() = nil error, want refusal: адрес базы объявлен двумя источниками %v, "+
					"и точка наката выбрала бы старшинство молча", tc.names)
			}
			for _, name := range tc.names {
				if !strings.Contains(err.Error(), name) {
					t.Fatalf("отказ обязан назвать источник %q, получено: %q", name, err.Error())
				}
			}
		})
	}
}

// TestDownHeadReader_RefusesAnAddressDeclaredTwice — второй читатель адреса
// (страж обратного хода свода) обязан отказывать тем же правилом: иначе `down`
// спросил бы голову цепочки у одной базы, а откатывал бы другую.
func TestDownHeadReader_RefusesAnAddressDeclaredTwice(t *testing.T) {
	tc := refusalCases()[0]
	opts := applyCase(t, tc.flag, tc.env, tc.file)

	_, err := headVersionFrom(opts, fstest.MapFS{})(context.Background())
	if err == nil {
		t.Fatal("headVersionFrom() = nil error, want refusal: адрес базы объявлен двумя источниками")
	}
	for _, name := range tc.names {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("отказ обязан назвать источник %q, получено: %q", name, err.Error())
		}
	}
}

// TestBuildRunner_AcceptsAnAddressDeclaredOnce — ПОЛОЖИТЕЛЬНЫЕ БЛИЗНЕЦЫ: каждый
// источник поодиночке принят. Соединение не открывается — сборка наката его не
// открывает, поэтому судится разбор, а не доступность базы.
func TestBuildRunner_AcceptsAnAddressDeclaredOnce(t *testing.T) {
	cases := []struct {
		name string
		flag string
		env  map[string]string
		file bool
	}{
		{name: "flag alone", flag: addrA},
		{name: "neutral env alone", env: map[string]string{"MIGRATOR_DSN": addrA}},
		{name: "legacy env alone", env: map[string]string{"KACHO_MIGRATOR_DSN": addrA}},
		{name: "service url env alone", env: map[string]string{"KANAME_REPOSITORY__POSTGRES__URL": addrB}},
		{name: "service config file alone", file: true},
		{name: "service split fields alone", env: map[string]string{"KANAME_DB_HOST": "pg-b", "KANAME_DB_NAME": "kaname"}},
		{name: "nothing declared: service default", env: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := applyCase(t, tc.flag, tc.env, tc.file)
			if _, err := buildRunner(opts, fstest.MapFS{}); err != nil {
				t.Fatalf("buildRunner() = %q, want nil: адрес объявлен одним источником, спорить нечему", err.Error())
			}
		})
	}
}

// TestBuildRunner_DoubleDeclarationRefusalDoesNotEchoTheAddress — отказ
// называет ИСТОЧНИКИ, а не их значения: строка подключения несёт пароль базы, а
// текст отказа уезжает в журнал пода.
func TestBuildRunner_DoubleDeclarationRefusalDoesNotEchoTheAddress(t *testing.T) {
	const password = "s3cret-never-in-a-log"
	opts := applyCase(t, "postgres://iam:"+password+"@pg-a:5432/kaname",
		map[string]string{"MIGRATOR_DSN": "postgres://iam:" + password + "@pg-b:5432/kaname"}, false)

	_, err := buildRunner(opts, fstest.MapFS{})
	if err == nil {
		t.Fatal("buildRunner() = nil error, want refusal for an address declared twice")
	}
	if strings.Contains(err.Error(), password) {
		t.Fatalf("текст отказа несёт пароль базы — он уезжает в журнал пода: %q", err.Error())
	}
	if strings.Contains(err.Error(), "pg-a") || strings.Contains(err.Error(), "pg-b") {
		t.Fatalf("текст отказа называет значения, а не источники: %q", err.Error())
	}
}
