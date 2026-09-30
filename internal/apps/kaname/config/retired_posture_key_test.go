// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retired_posture_key_test.go — СНЯТЫЙ КЛЮЧ ПОСАДКИ ЛИЧНОСТИ ОТВЕРГАЕТСЯ ВСЛУХ
// НА КАЖДОМ ПУТИ ПОДАЧИ ПРОЦЕССУ (kaname#363).
//
// У службы одна посадка — своя чеканка и свой вход человека, — и ключа, который
// её выбирал, больше нет. Загрузчик настройки незнакомых ключей не отвергает:
// у разбора задан только перевод значений, запрета на лишнее нет. Значит, снятый
// ключ, оставленный в профиле оператора, прошёл бы молча — «принято и
// проигнорировано», — а прежде он был ОБЯЗАТЕЛЕН и менял старт. Поэтому ключ
// отвергается вслух при любом значении, в том числе `own`, и отказ называет,
// что сделать.
//
// Путей подачи у процесса два: файл настройки (`KANAME_CONFIG_PATH`) и
// переменная окружения. Каждый судится своей пробой; законный близнец каждой —
// тот же вход без ключа, и он старт не роняет. Путь значений чарта судит
// `deploy/retired_posture_key_test.go`.
package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// retiredPostureKey / retiredPostureEnv — координаты снятого ключа так, как их
// знал оператор: путь в файле настройки и переменная окружения. Литералы, а не
// ссылки на объявление: проба судит, что загрузчик отвергает ИМЕННО то, что
// оператор мог написать, и объявление, переименованное по ошибке, не должно
// утащить пробу за собой.
const (
	retiredPostureKey = "authn.identity-provider"
	retiredPostureEnv = "KANAME_AUTHN__IDENTITY_PROVIDER"
)

// retiredPostureValues — каждое значение, которое профиль мог нести: законное
// прежде, снятое прежде и пустое. Отказ обязан наступать на всех трёх: ключ
// снят, а не значение.
var retiredPostureValues = []string{"own", "external", ""}

// writeSettingsFile кладёт файл настройки с телом body во временный каталог.
func writeSettingsFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("файл настройки не записан: %v", err)
	}
	return path
}

// requireRetiredKeyRefusal — загрузка отказала, и отказ называет снятый ключ,
// слово «снят» и шаг «удалите», а ещё — ТОТ путь подачи, по которому ключ
// пришёл: оператор, получивший отказ без пути, ищет строку не в том файле.
func requireRetiredKeyRefusal(t *testing.T, err error, via string) {
	t.Helper()
	if err == nil {
		t.Fatalf("загрузка приняла снятый ключ посадки (%s) — «принято и проигнорировано»: "+
			"профиль, написанный под прежнюю посадку, поднимался бы молча", via)
	}
	msg := err.Error()
	for _, want := range []string{retiredPostureKey, "retired", "remove", via} {
		if !strings.Contains(msg, want) {
			t.Fatalf("отказ о снятом ключе не называет %q:\n%s", want, msg)
		}
	}
}

// Путь 1 — ФАЙЛ НАСТРОЙКИ.
func TestRetiredPostureKeyIsRefusedFromTheSettingsFile(t *testing.T) {
	t.Setenv(retiredPostureEnv, "")
	if err := os.Unsetenv(retiredPostureEnv); err != nil {
		t.Fatalf("переменная не снята: %v", err)
	}
	refused := 0
	for _, v := range retiredPostureValues {
		if t.Run("value="+v, func(t *testing.T) {
			path := writeSettingsFile(t, "authn:\n  identity-provider: \""+v+"\"\n")
			_, err := config.Load(path)
			requireRetiredKeyRefusal(t, err, "settings file")
		}) {
			refused++
		}
	}
	t.Logf("перепись: путь «файл настройки» · значений %d · отвергнуто с верным текстом %d", len(retiredPostureValues), refused)
}

// Законный близнец пути 1: тот же файл без ключа — загрузка проходит. Без него
// отказ выше читался бы как «файл не читается», а не как «ключ снят».
func TestSettingsFileWithoutTheRetiredPostureKeyLoads(t *testing.T) {
	t.Setenv(retiredPostureEnv, "")
	if err := os.Unsetenv(retiredPostureEnv); err != nil {
		t.Fatalf("переменная не снята: %v", err)
	}
	path := writeSettingsFile(t, "authn:\n  domain: \"access.example.invalid\"\n")
	if _, err := config.Load(path); err != nil {
		t.Fatalf("файл без снятого ключа обязан загружаться, получено: %v", err)
	}
}

// Путь 2 — ПЕРЕМЕННАЯ ОКРУЖЕНИЯ. Заданная пустой — тоже заданная: под так её
// объявляет явно, и молча принятая пустая переменная — тот же класс.
func TestRetiredPostureKeyIsRefusedFromTheEnvironment(t *testing.T) {
	refused := 0
	for _, v := range retiredPostureValues {
		if t.Run("value="+v, func(t *testing.T) {
			t.Setenv(retiredPostureEnv, v)
			_, err := config.Load("")
			requireRetiredKeyRefusal(t, err, retiredPostureEnv)
		}) {
			refused++
		}
	}
	t.Logf("перепись: путь «окружение» · значений %d · отвергнуто с верным текстом %d", len(retiredPostureValues), refused)
}

// Законный близнец пути 2: переменная не задана — загрузка проходит.
func TestEnvironmentWithoutTheRetiredPostureVariableLoads(t *testing.T) {
	t.Setenv(retiredPostureEnv, "")
	if err := os.Unsetenv(retiredPostureEnv); err != nil {
		t.Fatalf("переменная не снята: %v", err)
	}
	if _, err := config.Load(""); err != nil {
		t.Fatalf("окружение без снятой переменной обязано загружаться, получено: %v", err)
	}
}
