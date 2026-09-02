// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config_test

// manifests_test.go — страж доставки манифестов модулей (задача #1875).
//
// Утверждается ОБЕ стороны: сочетание «опираемся и каталога не назвали» обязано
// отказать в пуске, а каждое законное сочетание — пройти. Односторонняя проба
// зеленела бы на страже, отвергающем всё.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
)

// manifestsChartShapedConfig — ТА ЖЕ форма, которую рендерит
// charts/kacho-iam/templates/configmap.yaml при объявленном источнике.
//
// Ключ YAML и тег структуры — два места об одном предмете, и расхождение между
// ними НЕ РОНЯЕТ НИ ОДНОЙ СБОРКИ: виперу нет дела до незнакомой секции, он молча
// её отбрасывает. Тогда посадка объявила бы каталог, процесс читал бы пустой
// путь, и оператор увидел бы «манифесты не доехали» при верной посадке.
const manifestsChartShapedConfig = `
manifests:
  dir: "/etc/kacho-iam/manifests"
  required: true
`

// TestLoadReadsTheManifestsSectionTheChartWrites — путь ключа, который пишет
// чарт, есть путь ключа, который читает Load.
func TestLoadReadsTheManifestsSectionTheChartWrites(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, manifestsChartShapedConfig))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Manifests.Dir != "/etc/kacho-iam/manifests" {
		t.Errorf("manifests.dir не доехал до структуры: получено %q — "+
			"ключ объявлен посадкой и отброшен разбором молча", cfg.Manifests.Dir)
	}
	if !cfg.Manifests.Required {
		t.Error("manifests.required не доехал до структуры — опора объявлена посадкой " +
			"и невидима стражу старта")
	}
}

func TestManifestsGuardRefusesRequiredWithoutDir(t *testing.T) {
	err := config.ManifestsConfig{Required: true, Dir: ""}.Validate()
	if err == nil {
		t.Fatal("страж молчит на «опираемся на манифесты и не сказали, откуда их читать» — " +
			"процесс поднялся бы, читая пустой путь, и это неотличимо от «модулей нет»")
	}
	// Отказ обязан НАЗЫВАТЬ ручку: оператор чинит по тексту, а не по догадке.
	for _, want := range []string{"manifests.required", "manifests.dir"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q — читатель не узнает, что править: %v", want, err)
		}
	}
}

func TestManifestsGuardStaysSilentOnEveryLawfulShape(t *testing.T) {
	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к отрицанию выше. Без него «отказ есть» неотличимо
	// от «страж отвергает любой вход».
	lawful := []struct {
		name string
		cfg  config.ManifestsConfig
	}{
		{"доставка не заведена", config.ManifestsConfig{}},
		{"каталог назван, опоры нет", config.ManifestsConfig{Dir: "/etc/kacho-iam/manifests"}},
		{"каталог назван, опора объявлена",
			config.ManifestsConfig{Dir: "/etc/kacho-iam/manifests", Required: true}},
	}
	for _, c := range lawful {
		t.Run(c.name, func(t *testing.T) {
			if err := c.cfg.Validate(); err != nil {
				t.Fatalf("законное сочетание отвергнуто: %v", err)
			}
		})
	}
}

// TestConfigValidateCallsTheManifestsGuard — страж провязан в общий страж старта.
//
// Своя проба у секции ничего не говорит о том, ЗОВЁТ ли её Config.Validate:
// объявленный и никем не позванный страж мёртв ровно так же, как ненаписанный.
func TestConfigValidateCallsTheManifestsGuard(t *testing.T) {
	cfg := config.Config{}
	cfg.Manifests = config.ManifestsConfig{Required: true}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "manifests.dir") {
		t.Fatalf("Config.Validate не несёт отказа секции manifests — страж объявлен и не позван: %v", err)
	}
}

// TestDocumentedManifestEnvNamesReachTheFields — ДОКУМЕНТИРОВАННОЕ имя
// переменной доезжает до поля.
//
// Класс, который эта проба закрывает, был внесён и найден в ней же: viper
// резолвит переменную ТОЛЬКО для ключа, который уже знает, а умолчания у обеих
// ручек нет намеренно. Без явной привязки оператор задал бы документированную
// переменную, процесс принял бы старт как «доставка не объявлена», и ручка
// выглядела бы настроенной, ничего не делая — «принято-и-проигнорировано»
// этажом ниже поля запроса.
func TestDocumentedManifestEnvNamesReachTheFields(t *testing.T) {
	t.Setenv("KACHO_IAM_MANIFESTS__DIR", "/mnt/манифесты")
	t.Setenv("KACHO_IAM_MANIFESTS__REQUIRED", "true")

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Manifests.Dir != "/mnt/манифесты" {
		t.Errorf("KACHO_IAM_MANIFESTS__DIR не доехала до поля: получено %q — "+
			"документированное имя переменной, которое ничего не делает, хуже недокументированного",
			cfg.Manifests.Dir)
	}
	if !cfg.Manifests.Required {
		t.Error("KACHO_IAM_MANIFESTS__REQUIRED не доехала до поля — опора объявлена оператором " +
			"и невидима стражу старта")
	}
}

// TestManifestEnvNamesAreNotBoundToAValue — привязка РЕГИСТРИРУЕТ ключ, но не
// даёт ему значения.
//
// Положительный контроль к пробе выше: без него «переменная доехала» было бы
// неотличимо от «привязка подставила непустое значение всякому старту», а это
// вернуло бы умолчание, которого здесь нет намеренно.
func TestManifestEnvNamesAreNotBoundToAValue(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Manifests.Dir != "" || cfg.Manifests.Required {
		t.Fatalf("незаданные переменные дали каталог %q и опору %v — привязка подставила "+
			"значение, и доставка выглядела бы объявленной на посадке, которая её не объявляла",
			cfg.Manifests.Dir, cfg.Manifests.Required)
	}
}
