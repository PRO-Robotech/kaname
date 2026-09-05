// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// manifests_test.go — страж доставки манифестов модулей (задача #1875).
//
// Утверждается ОБЕ стороны: сочетание «опираемся и каталога не назвали» обязано
// отказать в пуске, а каждое законное сочетание — пройти. Односторонняя проба
// зеленела бы на страже, отвергающем всё.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
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

// TestManifestsGuardRefusesADirWithoutReliance — ВТОРАЯ половина той же пары.
//
// Секция `manifests` есть ПАРА: намерение (`required`) и координата (`dir`).
// Половина пары хуже отсутствия обеих, потому что выглядит настроенной, —
// поэтому отвергаются ОБА неполных сочетания, а не одно (`security.md`
// §«Контроль, у которого нет МЕХАНИЗМА исполниться»).
//
// До этой правки сочетание «каталог назван, опоры нет» ПРИНИМАЛОСЬ и означало не
// то, что говорит: чтение включает сам каталог, и сорванную доставку `LoadDelivered`
// отвергает независимо от значения. То есть исполнимых состояний было два, а
// объявленных три (#1924).
func TestManifestsGuardRefusesADirWithoutReliance(t *testing.T) {
	err := config.ManifestsConfig{Required: false, Dir: "/etc/kacho-iam/manifests"}.Validate()
	if err == nil {
		t.Fatal("страж молчит на «каталог назван, опоры нет» — посадка объявила бы величину, " +
			"которая ничего не меняет: доставка читается и отвергается на сорванном каталоге " +
			"при любом required, значит объявленное «не опираемся» не исполняется ничем")
	}
	// Отказ обязан НАЗЫВАТЬ обе ручки: оператор чинит по тексту, а не по догадке.
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
		// Сочетаний ВСЕГО четыре, и здесь стоят ОБА законных. Третье
		// («каталог назван, опоры нет») переехало в отрицание выше вместе со
		// своим предметом: пара неполна в обе стороны одинаково.
		{"доставка не заведена", config.ManifestsConfig{}},
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
	// Те же две половины у ручек сборки (#1971): привязка обязана
	// РЕГИСТРИРОВАТЬ ключ, не давая ему значения. Подставленный допуск был бы
	// непуст всегда, и сборка выглядела бы судимой на посадке, её не объявлявшей.
	if cfg.Manifests.ComposeModel || cfg.Manifests.Admission != "" {
		t.Fatalf("незаданные переменные дали сборку %v и допуск %q — привязка подставила "+
			"значение, и умолчания здесь нет намеренно",
			cfg.Manifests.ComposeModel, cfg.Manifests.Admission)
	}
}

// ---------------------------------------------------------------------------
// СБОРКА МОДЕЛИ ПРАВ ИЗ ДОСТАВЛЕННЫХ МАНИФЕСТОВ И ЕЁ ДОПУСК (задача #1971).
//
// Приёмка `composed-model-admits-only-what-it-owns.md`, сценарии `ADM-B-01`…
// `ADM-B-06`; производитель — `З-02` (две величины секции `manifests`).
//
// Утверждаются ОБЕ стороны: каждое незаконное сочетание обязано ОТКАЗАТЬ В
// ПУСКЕ и назвать ручку, каждое законное — пройти. Односторонняя проба зеленела
// бы на страже, отвергающем всё (`ADM-B-04`, `ADM-B-05` — положительные
// близнецы, без них «отказывает всегда» неотличимо от «отказывает правильно»).
// ---------------------------------------------------------------------------

// manifestsComposeChartShapedConfig — форма, которую посадка обязана написать,
// объявив сборку. ТОТ ЖЕ класс, что и у `manifestsChartShapedConfig` выше: ключ
// YAML и тег структуры — два места об одном предмете, и расхождение между ними
// НЕ РОНЯЕТ НИ ОДНОЙ СБОРКИ (виперу нет дела до незнакомой секции).
//
// Ключи — kebab-case, как ВСЯ остальная конфигурация этого сервиса: camelCase
// тегов в пакете ноль (замер — `grep -o 'mapstructure:"[a-z]+[A-Z]'` по
// `*.go` пакета). Приёмка в прозе сценария пишет `composeModel`; это написание
// словаря `values.yaml` (`configMapName`, `mountPath`), а не словаря
// конфигурации службы, и молча принятое дало бы первый camelCase-ключ пакета —
// то есть второй способ писать одно и то же.
const manifestsComposeChartShapedConfig = `
manifests:
  dir: "/etc/kacho-iam/manifests"
  required: true
  compose-model: true
  admission: "content"
`

// TestLoadReadsTheCompositionKeysTheChartWrites — путь ключа, который пишет
// посадка, есть путь ключа, который читает Load.
func TestLoadReadsTheCompositionKeysTheChartWrites(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, manifestsComposeChartShapedConfig))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Manifests.ComposeModel {
		t.Error("manifests.compose-model не доехал до структуры — посадка объявила сборку " +
			"модели прав, и объявление отброшено разбором молча")
	}
	if cfg.Manifests.Admission != config.AdmissionByContent {
		t.Errorf("manifests.admission не доехал до структуры: получено %q — посадка назвала "+
			"допуск, и он невидим стражу старта", cfg.Manifests.Admission)
	}
}

// TestManifestsGuardRefusesCompositionWithoutAdmission — `ADM-B-01`.
//
// Состояния «сборка без допуска» НЕ СУЩЕСТВУЕТ: после снятия ограничений
// соседними задачами правка карты настроек кластера начинает определять модель
// прав установки, и допуск по содержанию — единственный производитель доверия к
// ней. Отказ, а не подстановка умолчания: подставленный допуск был бы непуст
// всегда, и сборка выглядела бы судимой на всякой посадке — включая ту, где
// допуска нет (тот же довод, что у `Dir` в шапке manifests.go).
func TestManifestsGuardRefusesCompositionWithoutAdmission(t *testing.T) {
	err := config.ManifestsConfig{
		Dir: "/etc/kacho-iam/manifests", Required: true,
		ComposeModel: true, Admission: "",
	}.Validate()
	if err == nil {
		t.Fatal("страж молчит на «сборка включена, допуск не объявлен» — процесс собрал бы " +
			"модель прав из доставленного и никем её не судил")
	}
	// Отказ обязан назвать ОБЕ ручки: оператор чинит по тексту, а не по догадке.
	for _, want := range []string{"manifests.compose-model", "manifests.admission"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q — читатель не узнает, что править: %v", want, err)
		}
	}
}

// TestManifestsGuardRefusesAnAdmissionOutsideTheClosedSet — `ADM-B-02`.
//
// Перечень допустимых значений ОБЪЯВЛЕН, а не подразумевается: отказ печатает
// и предъявленное значение, и перечень, иначе оператор чинит опечатку перебором.
func TestManifestsGuardRefusesAnAdmissionOutsideTheClosedSet(t *testing.T) {
	const bogus = "trust-the-cluster-map"
	err := config.ManifestsConfig{
		Dir: "/etc/kacho-iam/manifests", Required: true,
		ComposeModel: true, Admission: bogus,
	}.Validate()
	if err == nil {
		t.Fatalf("страж молчит на допуске %q вне закрытого набора — посадка объявила бы "+
			"судью, которого нет, и сборка поднялась бы несуждённой", bogus)
	}
	for _, want := range []string{"manifests.admission", bogus, config.AdmissionByContent} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q — предъявленное значение и перечень допустимых "+
				"обязаны стоять в тексте: %v", want, err)
		}
	}
}

// TestManifestsGuardRefusesCompositionWithoutDelivery — `ADM-B-03`.
//
// Случай НОВЫЙ: сегодня страж пары молчит на не объявленной вовсе паре
// намеренно (доставка вводится вперёд своих потребителей), и молчание перестаёт
// быть верным ровно тогда, когда объявлена сборка — собирать модель не из чего.
func TestManifestsGuardRefusesCompositionWithoutDelivery(t *testing.T) {
	err := config.ManifestsConfig{
		Dir: "", Required: false,
		ComposeModel: true, Admission: config.AdmissionByContent,
	}.Validate()
	if err == nil {
		t.Fatal("страж молчит на «сборка включена, доставки нет» — процесс поднялся бы, " +
			"собирая модель прав из пустого каталога, и это неотличимо от «модулей нет»")
	}
	for _, want := range []string{"manifests.compose-model", "manifests.dir"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q — читатель не узнает, что править: %v", want, err)
		}
	}
}

// TestManifestsGuardKeepsTheHalfPairRefusalItsOwnText — `ADM-B-03`, вторая
// половина: неполная ПОЛОВИНА пары доставки по-прежнему отвергается собственным
// текстом стража пары (#1924), и отказ сборки его НЕ ПОДМЕНЯЕТ — виновная ручка
// называется одна.
func TestManifestsGuardKeepsTheHalfPairRefusalItsOwnText(t *testing.T) {
	err := config.ManifestsConfig{
		Dir: "", Required: true,
		ComposeModel: true, Admission: config.AdmissionByContent,
	}.Validate()
	if err == nil {
		t.Fatal("страж молчит на неполной половине пары доставки")
	}
	if !strings.Contains(err.Error(), "kacho#1875") {
		t.Errorf("отказ половины пары подменён отказом сборки — виновных ручек названо "+
			"больше одной, и оператор чинит не то: %v", err)
	}
	// Прямое выражение «виновная ручка называется ОДНА»: текст половины пары не
	// вправе обвинять сборку — она объявлена честно и целиком.
	if strings.Contains(err.Error(), "manifests.compose-model") {
		t.Errorf("отказ половины пары называет ещё и manifests.compose-model, который "+
			"объявлен верно, — оператор снимет исправную ручку: %v", err)
	}
}

// TestManifestsGuardStaysSilentOnEveryLawfulCompositionShape — `ADM-B-04` и
// `ADM-B-05`: ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к четырём отрицаниям выше.
func TestManifestsGuardStaysSilentOnEveryLawfulCompositionShape(t *testing.T) {
	lawful := []struct {
		name string
		cfg  config.ManifestsConfig
	}{
		// ADM-B-04: сборка выключена. Посадка честно говорит «собирать нечего»;
		// величины допуска при этом не спрашивают — режима «только для стенда»
		// не заводится.
		{"сборка выключена, доставки нет", config.ManifestsConfig{}},
		{"сборка выключена, доставка объявлена целиком",
			config.ManifestsConfig{Dir: "/etc/kacho-iam/manifests", Required: true}},
		// ADM-B-05: сборка включена целиком — допуск из закрытого набора, пара
		// доставки объявлена.
		{"сборка включена целиком",
			config.ManifestsConfig{
				Dir: "/etc/kacho-iam/manifests", Required: true,
				ComposeModel: true, Admission: config.AdmissionByContent,
			}},
	}
	for _, c := range lawful {
		t.Run(c.name, func(t *testing.T) {
			if err := c.cfg.Validate(); err != nil {
				t.Fatalf("законное сочетание отвергнуто: %v", err)
			}
		})
	}
}

// TestConfigValidateCarriesTheCompositionRefusal — `ADM-B-06`, ПОЛОВИНА,
// производимая пакетом `config`.
//
// Утверждается ровно то, что здесь наблюдаемо: накопитель `Config.Validate`
// отказ секции НЕ ПРОГЛОТИЛ — возвращённая им ошибка называет ручку секции.
//
// Вторая половина сценария — «отказ доезжает до остановки процесса непогашенным»
// — этой пробой НЕ производится и производиться не может: она наблюдает возврат
// ошибки, ровно как `ADM-B-01`…`ADM-B-03`. Её производитель — гейт по дереву
// (`З-04` приёмки), и он живёт вне этого пакета.
func TestConfigValidateCarriesTheCompositionRefusal(t *testing.T) {
	cfg := config.Config{}
	cfg.Manifests = config.ManifestsConfig{
		Dir: "/etc/kacho-iam/manifests", Required: true, ComposeModel: true,
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "manifests.admission") {
		t.Fatalf("Config.Validate не несёт отказа секции manifests о допуске — страж "+
			"объявлен и не позван либо его отказ погашен накопителем: %v", err)
	}
}

// TestDocumentedCompositionEnvNamesReachTheFields — ДОКУМЕНТИРОВАННОЕ имя
// переменной доезжает до поля.
//
// Тот же класс, что у пары доставки: viper резолвит переменную ТОЛЬКО для
// ключа, который уже знает, а умолчания у обеих новых ручек нет намеренно. Без
// явной привязки оператор задал бы имя, процесс принял бы старт как «сборка не
// объявлена», и ручка выглядела бы настроенной, ничего не делая.
func TestDocumentedCompositionEnvNamesReachTheFields(t *testing.T) {
	t.Setenv("KACHO_IAM_MANIFESTS__COMPOSE_MODEL", "true")
	t.Setenv("KACHO_IAM_MANIFESTS__ADMISSION", config.AdmissionByContent)

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Manifests.ComposeModel {
		t.Error("KACHO_IAM_MANIFESTS__COMPOSE_MODEL не доехала до поля — документированное " +
			"имя переменной, которое ничего не делает, хуже недокументированного")
	}
	if cfg.Manifests.Admission != config.AdmissionByContent {
		t.Errorf("KACHO_IAM_MANIFESTS__ADMISSION не доехала до поля: получено %q",
			cfg.Manifests.Admission)
	}
}
