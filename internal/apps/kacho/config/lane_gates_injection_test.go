// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lane_gates_injection_test.go — ДОКАЗАТЕЛЬСТВО того, что гейты полосности
// способны упасть и способны смолчать.
//
// Инъекция идёт в ОБЕ стороны по каждой оси: дефект обязан находиться, законный
// близнец той же формы обязан молчать. Без второй половины гейт ловил бы форму,
// а не существо, и первый же ложный срабат его отключил бы.
//
// Пробы зовут ТЕ ЖЕ чистые тела, что исполняются на дереве (countCanonicalName-
// Declarations, inspectLaneTable, rangesOverLaneRequirements,
// getenvNamesMentioningProvider). Своя копия предиката разошлась бы с настоящим
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
// Ось 2 — полнота произведения (F4d-10).

// Дефект: у полосы не осталось НИ ОДНОГО обязательного элемента. Обязано
// находиться — это посадка, поднимающаяся без всякой проверки личности.
func TestInjection_ALaneWithNoRequiredElementIsFound(t *testing.T) {
	_, files := synthetic(t, map[string]string{
		"lane_requirements.go": `package config
var LaneRequirements = []LaneRequirement{
	{Lanes: laneExternal, Element: "адрес поставщика"},
}
`,
	})
	c := inspectLaneTable(files)
	if c.PerLane["laneOwn"] != 0 {
		t.Fatalf("перепись не заметила полосу без требований: own=%d", c.PerLane["laneOwn"])
	}
	if c.PerLane["laneExternal"] == 0 {
		t.Fatal("перепись потеряла и вторую полосу — предикат считает не то")
	}
}

// Дефект: таблица объявлена ДВАЖДЫ. Обязано находиться.
func TestInjection_ASecondLaneTableIsFound(t *testing.T) {
	_, files := synthetic(t, map[string]string{
		"a.go": `package config
var LaneRequirements = []LaneRequirement{{Lanes: laneExternal, Element: "а"}}
`,
		"b.go": `package config
var LaneRequirements = []LaneRequirement{{Lanes: laneOwn, Element: "б"}}
`,
	})
	if c := inspectLaneTable(files); c.Declarations != 2 {
		t.Fatalf("второе объявление таблицы не найдено: объявлений %d", c.Declarations)
	}
}

// ЗАКОННЫЙ БЛИЗНЕЦ: требование, объявленное для ОБЕИХ полос сразу, клеткой
// произведения не является — гейт на нём молчит. Без этого случая гейт краснел
// бы на всяком общем требовании.
func TestInjection_ARequirementDeclaredForBothLanesIsNotAFinding(t *testing.T) {
	_, files := synthetic(t, map[string]string{
		"lane_requirements.go": `package config
var LaneRequirements = []LaneRequirement{
	{Lanes: []IdentityProvider{IdentityProviderExternal, IdentityProviderOwn}, Element: "общее"},
	{Lanes: laneExternal, Element: "адрес поставщика"},
	{Lanes: laneOwn, Element: "своя чеканка"},
}
`,
	})
	c := inspectLaneTable(files)
	if c.PerLane["laneExternal"] == 0 || c.PerLane["laneOwn"] == 0 {
		t.Fatalf("общее требование не должно лишать полосу её собственных клеток: external=%d own=%d",
			c.PerLane["laneExternal"], c.PerLane["laneOwn"])
	}
	if c.Rows != 3 {
		t.Fatalf("строк таблицы %d, ожидалось 3", c.Rows)
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
func build() string { return os.Getenv("KACHO_IAM_HYDRA_ADMIN_TOKEN") }
`,
	})
	got := getenvNamesMentioningProvider(files["wiring.go"])
	if len(got) != 1 || got[0] != "KACHO_IAM_HYDRA_ADMIN_TOKEN" {
		t.Fatalf("ручка вне пакета настройки не найдена: %v", got)
	}
}

// Дефект в КОСВЕННОЙ форме: имя ручки вынесено умолчанием, а не доводом
// чтения. Предикат по доводу `os.Getenv` слепнет ровно здесь — то есть на
// первой же починенной ручке.
func TestInjection_AProviderKnobBehindAnIndirectionIsStillFound(t *testing.T) {
	_, files := synthetic(t, map[string]string{
		"wiring.go": `package main
func name() string { return "KACHO_IAM_HYDRA_ADMIN_TOKEN" }
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
func build() string { return os.Getenv("KACHO_IAM_HOOK_TOKEN") }
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
// Здесь объясняется, зачем нужна KACHO_IAM_HYDRA_ADMIN_TOKEN и почему её
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
