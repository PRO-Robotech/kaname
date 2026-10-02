// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lane_gates_injection_test.go — ДОКАЗАТЕЛЬСТВО того, что гейты полосности
// способны упасть и способны смолчать.
//
// Инъекция идёт в ОБЕ стороны по каждой оси: дефект обязан находиться, законный
// близнец той же формы обязан молчать. Ось полос посадки заменена осью стадий:
// посадка у службы одна (kaname#363). Без второй половины гейт ловил бы форму,
// а не существо, и первый же ложный срабат его отключил бы.
//
// Пробы зовут ТЕ ЖЕ чистые тела, что исполняются на дереве (inspectLaneTable,
// rangesOverLaneRequirements, getenvNamesMentioningProvider). Своя копия предиката разошлась бы с настоящим
// гейтом молча — и доказательство перестало бы относиться к нему.
package config_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// synthetic разбирает исходники-фикстуры в тот же вид, в каком гейт видит дерево.
func synthetic(t *testing.T, sources map[string]string) (*token.FileSet, map[string]*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	out := map[string]*ast.File{}
	for name, src := range sources {
		f, err := parser.ParseFile(fset, name, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("фикстура %s не разобрана: %v", name, err)
		}
		out[name] = f
	}
	return fset, out
}

// ─────────────────────────────────────────────────────────────────────────────
// Ось 2 — полнота таблицы по стадиям (F4d-10).

// Дефект: у стадии сборки не осталось НИ ОДНОГО требования. Обязано находиться —
// это старт, поднимающийся без проверки провязки.
func TestInjection_AStageWithNoRequirementIsFound(t *testing.T) {
	_, files := synthetic(t, map[string]string{
		"lane_requirements.go": `package config
var LaneRequirements = []LaneRequirement{
	{Element: "своя чеканка", Stage: LaneStageConfig},
}
`,
	})
	c := inspectLaneTable(files)
	if c.PerStage["LaneStageWiring"] != 0 {
		t.Fatalf("перепись не заметила стадию без требований: сборка=%d", c.PerStage["LaneStageWiring"])
	}
	if c.PerStage["LaneStageConfig"] != 1 {
		t.Fatal("перепись потеряла и вторую стадию — предикат считает не то")
	}
}

// Дефект: строка без стадии. Сумма по стадиям обязана разойтись с числом строк.
func TestInjection_ARowWithoutAStageIsFound(t *testing.T) {
	_, files := synthetic(t, map[string]string{
		"lane_requirements.go": `package config
var LaneRequirements = []LaneRequirement{
	{Element: "своя чеканка", Stage: LaneStageConfig},
	{Element: "без стадии"},
}
`,
	})
	c := inspectLaneTable(files)
	if c.Rows != 2 || c.PerStage["LaneStageConfig"]+c.PerStage["LaneStageWiring"] != 1 {
		t.Fatalf("строка без стадии не видна расхождением: строк %d, по стадиям %v", c.Rows, c.PerStage)
	}
}

// Дефект: таблица объявлена ДВАЖДЫ. Обязано находиться.
func TestInjection_ASecondLaneTableIsFound(t *testing.T) {
	_, files := synthetic(t, map[string]string{
		"a.go": `package config
var LaneRequirements = []LaneRequirement{{Element: "а", Stage: LaneStageConfig}}
`,
		"b.go": `package config
var LaneRequirements = []LaneRequirement{{Element: "б", Stage: LaneStageWiring}}
`,
	})
	if c := inspectLaneTable(files); c.Declarations != 2 {
		t.Fatalf("второе объявление таблицы не найдено: объявлений %d", c.Declarations)
	}
}

// ЗАКОННЫЙ БЛИЗНЕЦ: таблица с требованиями на обеих стадиях — гейт молчит, и
// стадия, названная квалифицированным именем, считается той же стадией.
func TestInjection_ATableWithBothStagesIsSilent(t *testing.T) {
	_, files := synthetic(t, map[string]string{
		"lane_requirements.go": `package config
var LaneRequirements = []LaneRequirement{
	{Element: "своя чеканка", Stage: LaneStageConfig},
	{Element: "подписант провязан", Stage: config.LaneStageWiring},
}
`,
	})
	c := inspectLaneTable(files)
	if c.PerStage["LaneStageConfig"] != 1 || c.PerStage["LaneStageWiring"] != 1 {
		t.Fatalf("законная таблица прочитана неверно: %v", c.PerStage)
	}
	if c.Rows != 2 {
		t.Fatalf("строк таблицы %d, ожидалось 2", c.Rows)
	}
}

// Дефект: проба перестала быть табличной — обходит свой перечень, а не
// объявление. Обязано находиться.
func TestInjection_AProbeThatStoppedWalkingTheTableIsFound(t *testing.T) {
	_, files := synthetic(t, map[string]string{
		"probe_test.go": `package config_test
func TestX(t *testing.T) {
	for _, r := range []string{"а", "б"} { _ = r }
}
`,
	})
	if rangesOverLaneRequirements(files["probe_test.go"]) {
		t.Fatal("гейт счёл табличной пробу, которая обходит собственный перечень")
	}
}

// Законный близнец: проба, обходящая объявление по квалифицированному имени.
// Гейт молчит.
func TestInjection_ATableDrivenProbeIsSilent(t *testing.T) {
	_, files := synthetic(t, map[string]string{
		"probe_test.go": `package config_test
func TestX(t *testing.T) {
	for _, r := range config.LaneRequirements { _ = r }
}
`,
	})
	if !rangesOverLaneRequirements(files["probe_test.go"]) {
		t.Fatal("законная табличная проба объявлена находкой")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Ось 3 — видимость ручек разговора с поставщиком (F4d-11).

// Дефект: ручка читается прямым обращением к окружению вне пакета настройки.
// Обязана находиться.
func TestInjection_AProviderKnobReadOutsideTheConfigPackageIsFound(t *testing.T) {
	_, files := synthetic(t, map[string]string{
		"wiring.go": `package main
func build() string { return os.Getenv("KANAME_HYDRA_ADMIN_TOKEN") }
`,
	})
	got := getenvNamesMentioningProvider(files["wiring.go"])
	if len(got) != 1 || got[0] != "KANAME_HYDRA_ADMIN_TOKEN" {
		t.Fatalf("ручка вне пакета настройки не найдена: %v", got)
	}
}

// Дефект в КОСВЕННОЙ форме: имя ручки вынесено умолчанием, а не доводом
// чтения. Предикат по доводу `os.Getenv` слепнет ровно здесь — то есть на
// первой же починенной ручке.
func TestInjection_AProviderKnobBehindAnIndirectionIsStillFound(t *testing.T) {
	_, files := synthetic(t, map[string]string{
		"wiring.go": `package main
func name() string { return "KANAME_HYDRA_ADMIN_TOKEN" }
func build() string { return os.Getenv(name()) }
`,
	})
	if got := getenvNamesMentioningProvider(files["wiring.go"]); len(got) != 1 {
		t.Fatalf("ручка за косвенностью не найдена: %v — предикат ломается раньше своего предмета", got)
	}
}

// Законный близнец: ручка, к разговору с поставщиком не относящаяся, находкой
// не считается.
func TestInjection_AnUnrelatedKnobIsSilent(t *testing.T) {
	_, files := synthetic(t, map[string]string{
		"wiring.go": `package main
func build() string { return os.Getenv("KANAME_JWKS_ENC_KEY") }
`,
	})
	if got := getenvNamesMentioningProvider(files["wiring.go"]); len(got) != 0 {
		t.Fatalf("посторонняя ручка объявлена находкой: %v", got)
	}
}

// Законный близнец второго рода: ПРОЗА, называющая ручку в комментарии.
// Комментарий литералом не является и в перепись не входит — иначе гейт краснел
// бы на собственном объяснении.
func TestInjection_ProseNamingTheKnobIsSilent(t *testing.T) {
	_, files := synthetic(t, map[string]string{
		"doc.go": `package main
// Здесь объясняется, зачем нужна KANAME_HYDRA_ADMIN_TOKEN и почему её
// читают через настройку.
func nothing() {}
`,
	})
	if got := getenvNamesMentioningProvider(files["doc.go"]); len(got) != 0 {
		t.Fatalf("проза объявлена находкой: %v", got)
	}
}

// Перепись обязана падать на ПУСТОМ обходе: «ноль находок» должно быть отличимо
// от «ноль прочитанного».
func TestInjection_AnEmptyWalkIsNotSilentSuccess(t *testing.T) {
	_, files := synthetic(t, map[string]string{})
	if c := inspectLaneTable(files); c.Rows != 0 || c.Declarations != 0 {
		t.Fatalf("пустой обход дал непустую перепись: %+v", c)
	}
	// Сам гейт на таком обходе падает (parsePackageFiles → t.Fatal); здесь
	// закреплено, что перепись честно показывает ноль, а не выдумывает строки.
}
