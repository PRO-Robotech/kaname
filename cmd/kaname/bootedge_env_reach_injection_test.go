// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// bootedge_env_reach_injection_test.go — доказательство того, что гейт
// досягаемости имён таблицы рёбер СПОСОБЕН упасть, и падает на своём предмете
// (#2469).
//
// ─────────────────────────────────────────────────────────────────────────────
// ИНЪЕКЦИЯ РОНЯЕТ ТОЛЬКО ПРОВЕРЯЕМОЕ
//
// Ни один исходник дерева не правится: и разбор, и суждение принимают вход
// ДОВОДОМ — байты исходника и функция ответа о досягаемости. Настоящее
// окружение прогона не трогается вовсе, поэтому соседний гейт досягаемости
// самоотчёта и страж посадки его не видят.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОСИ
//
//  1. ИНЕРТНАЯ РУЧКА — названа находкой с координатой. Законный близнец — та же
//     ручка, до поля доезжающая: молчание.
//  2. ДВЕ ФОРМЫ ЛИТЕРАЛА. Ручки объявляются и с явным типом, и внутри среза,
//     где тип задан элементом. Форма, о которой распознаватель не знает, даёт
//     не красное и не зелёное, а МОЛЧАНИЕ; сегодняшняя таблица написана ВТОРОЙ
//     формой, поэтому разбор, знающий только первую, прочитал бы ноль ручек и
//     отчитался бы «инертных нет».
//  3. ПРОЗА НЕ КООРДИНАТА. Имя ручки в поле объяснения и в комментарии рядом
//     предметом не является: предикат по подстроке краснел бы на собственном
//     объяснении проверяемого — а объяснений этих ручек в дереве десятки.
//  4. ПУСТАЯ РУЧКА ИСКЛЮЧЕНИЯ — объявленная величина («исключения не бывает»),
//     а не координата.
//  5. ЧУЖОЙ ТИП с полем того же имени не судится.
//  6. ПУСТОЙ ОБХОД — находка, а не тишина: «инертных нет» верно тривиально,
//     когда не прочитано ничего.

import (
	"strings"
	"testing"
)

// allReach / noneReach — ответы о досягаемости, подаваемые доводом.
func allReach(string) (bool, string) { return true, "подано инъекцией" }
func noneReach(string) (bool, string) {
	return false, "подано инъекцией: величина не прочитана"
}

// tableSource — таблица рёбер, написанная ВТОРОЙ формой (срез с безымянными
// элементами) — той, которой написана настоящая.
func tableSource(knob, plaintextKnob string) string {
	return `package main

func edges() []httpEdgeTLS {
	return []httpEdgeTLS{
		{
			name: "ребро", knob: "` + knob + `",
			why:           "по проводу едет KANAME_ПРОЗА_ИЗ_ОБЪЯСНЕНИЯ, и это не координата",
			plaintextKnob: "` + plaintextKnob + `",
		},
	}
}
`
}

func knobNames(t *testing.T, src string) []string {
	t.Helper()
	knobs, err := bootEdgeKnobsIn("edges.go", []byte(src))
	if err != nil {
		t.Fatalf("синтетический исходник не разбирается: %v", err)
	}
	var out []string
	for _, k := range knobs {
		out = append(out, k.Name)
	}
	return out
}

// TestBootEdgeInjection_InertKnobIsCaught — инертная ручка названа находкой с
// координатой.
func TestBootEdgeInjection_InertKnobIsCaught(t *testing.T) {
	knobs, err := bootEdgeKnobsIn("edges.go", []byte(tableSource("KANAME_X_ENABLE", "")))
	if err != nil {
		t.Fatalf("синтетический исходник не разбирается: %v", err)
	}
	findings, census := auditBootEdgeKnobs(1, knobs, noneReach)
	if len(findings) != 1 {
		t.Fatalf("инертная ручка дала находок %d, ожидалась 1: %v", len(findings), findings)
	}
	for _, want := range []string{"KANAME_X_ENABLE", "edges.go:"} {
		if !strings.Contains(findings[0], want) {
			t.Errorf("находка не называет %q: %s", want, findings[0])
		}
	}
	if census.Reached != 0 || census.Named != 1 {
		t.Errorf("перепись не сошлась: названо %d, доезжает %d", census.Named, census.Reached)
	}
}

// TestBootEdgeInjection_ReachableKnobStaysSilent — ЗАКОННЫЙ БЛИЗНЕЦ: та же
// ручка, до поля доезжающая.
//
// Без него красное выше не доказывает ничего: суждение, объявляющее инертной
// любую ручку, дало бы тот же результат.
func TestBootEdgeInjection_ReachableKnobStaysSilent(t *testing.T) {
	knobs, err := bootEdgeKnobsIn("edges.go", []byte(tableSource("KANAME_X_ENABLE", "")))
	if err != nil {
		t.Fatalf("синтетический исходник не разбирается: %v", err)
	}
	findings, census := auditBootEdgeKnobs(1, knobs, allReach)
	if len(findings) != 0 {
		t.Fatalf("досягаемая ручка объявлена находкой: %v", findings)
	}
	if census.Reached != 1 {
		t.Fatalf("доезжает %d, ожидалось 1", census.Reached)
	}
}

// TestBootEdgeInjection_BothLiteralFormsAreRead — обе законные формы литерала.
//
// Ось несущая: сегодняшняя таблица написана формой без явного типа, и
// распознаватель, знающий только явную, прочитал бы НОЛЬ — то есть отчитался бы
// «инертных нет», не спросив ни об одной ручке.
func TestBootEdgeInjection_BothLiteralFormsAreRead(t *testing.T) {
	implicit := tableSource("KANAME_IMPLICIT_ENABLE", "")
	explicit := `package main

var edge = httpEdgeTLS{name: "ребро", knob: "KANAME_EXPLICIT_ENABLE"}
`
	if got := knobNames(t, implicit); len(got) != 1 || got[0] != "KANAME_IMPLICIT_ENABLE" {
		t.Errorf("форма БЕЗ явного типа не прочитана: %v", got)
	}
	if got := knobNames(t, explicit); len(got) != 1 || got[0] != "KANAME_EXPLICIT_ENABLE" {
		t.Errorf("форма С явным типом не прочитана: %v", got)
	}
}

// TestBootEdgeInjection_ConcatenatedNameIsRead — склейка литералов остаётся
// координатой: имена в этом дереве переносятся по строкам.
func TestBootEdgeInjection_ConcatenatedNameIsRead(t *testing.T) {
	src := `package main

var edge = httpEdgeTLS{knob: "KANAME_" + "SPLIT_ENABLE"}
`
	if got := knobNames(t, src); len(got) != 1 || got[0] != "KANAME_SPLIT_ENABLE" {
		t.Errorf("склейка литералов не прочитана координатой: %v", got)
	}
}

// TestBootEdgeInjection_ProseIsNotACoordinate — имя ручки в поле объяснения и в
// комментарии рядом координатой НЕ является.
func TestBootEdgeInjection_ProseIsNotACoordinate(t *testing.T) {
	got := knobNames(t, tableSource("KANAME_X_ENABLE", ""))
	if len(got) != 1 {
		t.Fatalf("прочитано имён %d, ожидалось 1: %v", len(got), got)
	}
	for _, name := range got {
		if strings.Contains(name, "ПРОЗА") {
			t.Fatalf("имя из поля объяснения зачтено координатой: %q", name)
		}
	}

	commented := `package main

// KANAME_ИЗ_КОММЕНТАРИЯ_ENABLE — про эту ручку сказано ниже.
var edge = httpEdgeTLS{knob: "KANAME_X_ENABLE"}
`
	for _, name := range knobNames(t, commented) {
		if strings.Contains(name, "КОММЕНТАРИЯ") {
			t.Fatalf("имя из комментария зачтено координатой: %q — гейт судил бы прозу", name)
		}
	}
}

// TestBootEdgeInjection_EmptyPlaintextKnobIsNotACoordinate — пустая ручка
// исключения есть объявленная величина, а не координата.
//
// Без этой ветви гейт краснел бы на КАЖДОМ ребре, у которого исключения не
// бывает, — то есть на пяти из шести, и первый же ложный срабат снял бы его.
func TestBootEdgeInjection_EmptyPlaintextKnobIsNotACoordinate(t *testing.T) {
	if got := knobNames(t, tableSource("KANAME_X_ENABLE", "")); len(got) != 1 {
		t.Fatalf("пустая ручка исключения зачтена координатой: %v", got)
	}
	got := knobNames(t, tableSource("KANAME_X_ENABLE", "KANAME_X_PLAINTEXT_ACKNOWLEDGED"))
	if len(got) != 2 {
		t.Fatalf("непустая ручка исключения НЕ прочитана: %v", got)
	}
}

// TestBootEdgeInjection_ForeignTypeIsNotJudged — чужой тип с полем того же
// имени предметом не является.
func TestBootEdgeInjection_ForeignTypeIsNotJudged(t *testing.T) {
	src := `package main

type somethingElse struct{ knob string }

var x = somethingElse{knob: "KANAME_ЧУЖОЙ_ENABLE"}
`
	if got := knobNames(t, src); len(got) != 0 {
		t.Fatalf("поле чужого типа зачтено координатой ребра подъёма: %v", got)
	}
}

// TestBootEdgeInjection_EmptyWalkIsAFinding — обход без файлов и обход без
// ручек: оба обязаны быть находкой, а не тишиной.
func TestBootEdgeInjection_EmptyWalkIsAFinding(t *testing.T) {
	findings, _ := auditBootEdgeKnobs(0, nil, allReach)
	if len(findings) != 1 || !strings.Contains(findings[0], "прочитано 0") {
		t.Fatalf("обход без файлов не назван беспредметным: %v", findings)
	}

	findings, census := auditBootEdgeKnobs(41, nil, allReach)
	if len(findings) != 1 || !strings.Contains(findings[0], "не назвала ни одной ручки") {
		t.Fatalf("обход без ручек не назван беспредметным: %v", findings)
	}
	if census.Named != 0 {
		t.Fatalf("названо %d при пустом входе", census.Named)
	}
}

// TestBootEdgeInjection_TheSameKnobIsCountedOnce — одна и та же ручка,
// названная дважды, считается одним именем: перепись должна называть ИМЕНА, а
// не вхождения, иначе «доезжает 6» и «названо 6» разошлись бы на повторе.
func TestBootEdgeInjection_TheSameKnobIsCountedOnce(t *testing.T) {
	src := `package main

var edges = []httpEdgeTLS{
	{knob: "KANAME_SAME_ENABLE"},
	{knob: "KANAME_SAME_ENABLE"},
}
`
	knobs, err := bootEdgeKnobsIn("edges.go", []byte(src))
	if err != nil {
		t.Fatalf("синтетический исходник не разбирается: %v", err)
	}
	if len(knobs) != 2 {
		t.Fatalf("вхождений прочитано %d, ожидалось 2", len(knobs))
	}
	_, census := auditBootEdgeKnobs(1, knobs, allReach)
	if census.Named != 1 || census.Reached != 1 {
		t.Fatalf("повтор имени учтён дважды: названо %d, доезжает %d", census.Named, census.Reached)
	}
}
