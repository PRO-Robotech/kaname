// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package standalonetargets_test

// probe_text_injection_test.go — находка «упали пробы модуля» несёт ТЕКСТ
// отказа каждой упавшей пробы, а не только её имя (задача #618, урок разбора
// kaname#1069).
//
// # Предмет
//
// Красное задания «цели рецепта в самостоятельном клоне» читалось так:
//
//	УПАЛИ:
//	    github.com/PRO-Robotech/kaname/internal/check TestNewMigrationOutranksEveryAppliedOne
//
// и ни строкой больше. Имя посылает читателя искать причину, текст её называет:
// диагноз пришлось ставить гипотезой и отдельным воспроизведением. Перечень
// печатает рецепт `scripts/test-standalone.sh` из машинного вывода `go test
// -json`, где текст отказа ЕСТЬ, — он его отбрасывал.
//
// # Как построена проба
//
// Синтетический модуль из двух проб — упавшей и зелёной, пишущей в журнал, — и
// НАСТОЯЩИЙ рецепт модуля, скопированный в него. Цель зовётся тем же раннером,
// что и в гейте, и судится тем же RunTargets: утверждение стоит на строке,
// которую печатает гейт, а не на выводе рецепта в обход разбора.
//
// Пара однофактная внутри одного прогона: текст упавшей пробы обязан дойти до
// находки, журнал зелёной — нет (иначе рецепт выгружает весь вывод, и находка
// тонет в шуме, а хвост вывода обрезает именно текст).

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/tools/standalonetargets"
)

const (
	probeFailText  = "ТЕКСТ ОТКАЗА ПРОБЫ: база сравнения origin/1054 в этом клоне не разрешается"
	probePassNoise = "ЖУРНАЛ ЗЕЛЁНОЙ ПРОБЫ: в находку не едет"
)

// runRealRecipe — НАСТОЯЩИЙ рецепт проб модуля на синтетическом модуле, чей
// файл проб несёт probes (тело без строки package), позванный тем же раннером и
// судимый тем же RunTargets, что и в гейте.
func runRealRecipe(t *testing.T, probes string) ([]standalonetargets.Finding, []standalonetargets.Unmet) {
	t.Helper()
	if testing.Short() {
		t.Skip("зовёт go test синтетического модуля отдельным процессом — прогон интеграционного порядка")
	}
	wd, err := os.Getwd()
	require.NoError(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: каталог прогона не назван")
	root, err := standalonetargets.ModuleRootFrom(wd)
	require.NoError(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не назван")
	script, err := os.ReadFile(filepath.Join(root, "scripts", "test-standalone.sh"))
	require.NoError(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: рецепта проб модуля нет")

	dir := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		abs := filepath.Join(dir, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(abs), 0o750))
		require.NoError(t, os.WriteFile(abs, []byte(body), 0o600))
	}
	write("go.mod", "module example.invalid/probe\n\ngo 1.21\n")
	write("probe_test.go", "package probe\n\n"+probes)
	write("scripts/test-standalone.sh", string(script))
	write("Makefile", "test-standalone:\n\t@bash scripts/test-standalone.sh $(ARGS)\n")

	targets := []standalonetargets.Target{{Name: "test-standalone", Desc: "пробы модуля"}}
	t.Setenv("GOWORK", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	findings, unmet, err := standalonetargets.RunTargets(dir, targets, makeRunner(t))
	require.NoError(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: цель не запустилась")
	return findings, unmet
}

// TestProbeFailure_FindingCarriesTheRefusalText — инъекция: проба модуля падает
// с названным текстом; находка гейта обязана его нести.
func TestProbeFailure_FindingCarriesTheRefusalText(t *testing.T) {
	findings, unmet := runRealRecipe(t, fmt.Sprintf(`import "testing"

func TestRefuses(t *testing.T) { t.Fatalf(%q) }

func TestPassesWithANote(t *testing.T) { t.Log(%q) }
`, probeFailText, probePassNoise))
	require.Empty(t, unmet, "упавшая проба подана третьим исходом")
	require.Len(t, findings, 1, "упавшая проба синтетического модуля не стала находкой")
	require.True(t, findings[0].Probes,
		"рецепт не объявил меткой, что упали пробы — род находки не различён:\n%s", findings[0].Tail)

	got := findings[0].String()
	require.Containsf(t, got, "TestRefuses", "находка не назвала упавшую пробу:\n%s", got)
	require.Containsf(t, got, probeFailText,
		"находка назвала упавшую пробу по имени, но не несёт её ТЕКСТА отказа — читатель "+
			"ставит диагноз гипотезой вместо цитаты:\n%s", got)
	require.NotContainsf(t, got, probePassNoise,
		"журнал зелёной пробы доехал до находки — рецепт выгружает весь вывод, и текст "+
			"отказа тонет в шуме:\n%s", got)
}

// markInProbeText — текст отказа пробы, ВТОРАЯ строка которого начинается
// меткой третьего исхода. Так пишет проба, судящая чужую предпосылку и упавшая
// на ней: слова метки в её тексте законны, но вердикт о ней — красное.
const markInProbeText = "первая строка отказа пробы\n" +
	standalonetargets.UnmetPremiseMark + ": слова метки в тексте упавшей пробы"

// TestProbeFailure_MarkInsideTheProbeTextIsStillAFinding — инъекция маски
// (задача #618). Рецепт печатает строки упавшей пробы под её именем, и вторая
// строка её текста встаёт меткой ПЕРВОЙ на своей строке. Гейт, спросивший о
// третьем исходе раньше, чем о том, упали ли пробы, подавал такое красное
// третьим исходом: «находок 0 · условие не создано 1» — зелёный вердикт.
func TestProbeFailure_MarkInsideTheProbeTextIsStillAFinding(t *testing.T) {
	findings, unmet := runRealRecipe(t, fmt.Sprintf(`import "testing"

func TestRefusesWithTheMark(t *testing.T) { t.Fatal(%q) }
`, markInProbeText))
	require.Emptyf(t, unmet,
		"метка в тексте УПАВШЕЙ пробы подала красное третьим исходом — гейт зеленеет на "+
			"красной пробе:\n%v", unmet)
	require.Len(t, findings, 1, "упавшая проба с меткой в тексте не стала находкой")
	require.True(t, findings[0].Probes, "род находки не различён:\n%s", findings[0].Tail)
	require.Contains(t, findings[0].String(), "TestRefusesWithTheMark")
}

// panicFirst, panicSecond — две строки сообщения паники: паника — законная
// форма отказа пробы, и её сообщение печатается ДО трассы горутин.
const (
	panicFirst  = "ТЕКСТ ПАНИКИ: первая строка сообщения"
	panicSecond = "ТЕКСТ ПАНИКИ: вторая строка сообщения"
)

// TestProbeFailure_PanicFindingCarriesThePanicText — инъекция: проба падает
// паникой с двухстрочным сообщением на глубине стека. За сообщением идёт трасса
// горутин, и последние строки текста пробы — это трасса, а сообщение отрезано.
// Находка обязана нести ТЕКСТ паники, а не кадры стека.
func TestProbeFailure_PanicFindingCarriesThePanicText(t *testing.T) {
	findings, unmet := runRealRecipe(t, fmt.Sprintf(`import "testing"

func deeper(n int) {
	if n == 0 {
		panic(%q)
	}
	deeper(n - 1)
}

func TestPanics(t *testing.T) { deeper(12) }
`, panicFirst+"\n"+panicSecond))
	require.Empty(t, unmet, "упавшая паникой проба подана третьим исходом")
	require.Len(t, findings, 1, "упавшая паникой проба не стала находкой")
	got := findings[0].String()
	require.Containsf(t, got, "TestPanics", "находка не назвала упавшую пробу:\n%s", got)
	require.Containsf(t, got, panicFirst,
		"находка несёт трассу горутин, а сообщение паники отрезано:\n%s", got)
	require.Containsf(t, got, panicSecond,
		"находка несёт лишь первую строку многострочного сообщения паники:\n%s", got)
}

// probeReport — вывод рецепта той формы, что печатает `scripts/test-standalone.sh`
// при многих упавших пробах: текст ПЕРВОЙ стоит далеко от конца вывода (за
// пределом прежнего хвоста в 25 строк, в пределах предела рецепта). mark —
// печатает ли рецепт метку «упали пробы».
func probeReport(mark bool) string {
	var b strings.Builder
	b.WriteString("  УПАЛИ:\n")
	b.WriteString("    example.invalid/probe TestFirst\n")
	b.WriteString("      " + probeFailText + "\n")
	for i := range 55 {
		fmt.Fprintf(&b, "    example.invalid/probe TestNext%02d\n      отказ %02d\n", i, i)
	}
	if mark {
		b.WriteString("ПРОБЫ УПАЛИ: см. перечень выше\n")
	}
	b.WriteString("make: *** [Makefile:207: test-standalone] Error 1\n")
	return b.String()
}

// TestProbeFailure_TailKeepsTheEarliestRefusalText — инъекция в хвост: упало
// много проб, текст ПЕРВОЙ стоит далеко от конца вывода. Хвост находки «упали
// пробы» обязан его удержать: перечень печатает рецепт, и его предел — свой.
func TestProbeFailure_TailKeepsTheEarliestRefusalText(t *testing.T) {
	targets := []standalonetargets.Target{{Name: "test-standalone", Desc: "пробы модуля"}}
	findings, _, err := standalonetargets.RunTargets("посадка", targets,
		func(_, _ string) (int, string, error) { return 2, probeReport(true), nil })
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.True(t, findings[0].Probes)
	require.Containsf(t, findings[0].String(), probeFailText,
		"хвост находки обрезал текст отказа первой упавшей пробы:\n%s", findings[0].String())
}

// TestProbeFailure_RecipeFindingKeepsItsShortTail — законный близнец: тот же
// вывод БЕЗ метки «упали пробы» (отказала сама цель). Отличается одним фактом —
// меткой; хвост такой находки остаётся прежним, коротким: длинный хвост — свойство
// перечня проб, а не всякого отказа.
func TestProbeFailure_RecipeFindingKeepsItsShortTail(t *testing.T) {
	targets := []standalonetargets.Target{{Name: "test-standalone", Desc: "пробы модуля"}}
	findings, _, err := standalonetargets.RunTargets("посадка", targets,
		func(_, _ string) (int, string, error) { return 2, probeReport(false), nil })
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.False(t, findings[0].Probes)
	require.NotContainsf(t, findings[0].String(), probeFailText,
		"хвост отказа самой цели вырос вместе с хвостом перечня проб:\n%s", findings[0].String())
}

// --- Метка третьего исхода в тексте УПАВШЕЙ пробы -----------------------------
//
// Упавшая проба — вердикт, и слова метки в её тексте его не снимают. Пробы
// упавшие объявляют о себе ДВУМЯ производителями: рецепт проб модуля — своей
// меткой (ProbeFailureMark), `go test` в рецепте, зовущем его напрямую
// (`cla-check`), — строкой `--- FAIL:`. Каждой форме — пара однофактных
// близнецов: с признаком упавшей пробы — находка, без него та же метка — третий
// исход, как и прежде.

// TestRun_MarkInTheTextOfAFailedProbeIsAFinding — ось «рецепт проб модуля».
func TestRun_MarkInTheTextOfAFailedProbeIsAFinding(t *testing.T) {
	targets := []standalonetargets.Target{{Name: "test-standalone", Desc: "пробы модуля"}}
	out := "  УПАЛИ:\n" +
		"    example.invalid/probe TestRefusesWithTheMark\n" +
		"      probe_test.go:5: первая строка отказа пробы\n" +
		"      " + standalonetargets.UnmetPremiseMark + ": слова метки в тексте упавшей пробы\n" +
		standalonetargets.ProbeFailureMark + " см. перечень выше\n" +
		"make: *** [Makefile:2: test-standalone] Error 1\n"
	findings, unmet, err := standalonetargets.RunTargets("посадка", targets,
		func(_, _ string) (int, string, error) { return 2, out, nil })
	require.NoError(t, err)
	require.Emptyf(t, unmet, "метка в тексте упавшей пробы подала красное третьим исходом:\n%v", unmet)
	require.Len(t, findings, 1)
	require.True(t, findings[0].Probes)
}

// TestRun_MarkPrintedByTheRecipeItselfIsStillUnmet — законный близнец: тот же
// вывод БЕЗ признака упавших проб — метку напечатал сам рецепт. Отличается одним
// фактом, и третий исход остаётся третьим исходом.
func TestRun_MarkPrintedByTheRecipeItselfIsStillUnmet(t *testing.T) {
	targets := []standalonetargets.Target{{Name: "test-standalone", Desc: "пробы модуля"}}
	out := "  " + standalonetargets.UnmetPremiseMark + ": дерева платформы рядом нет\n" +
		"make: *** [Makefile:2: test-standalone] Error 1\n"
	findings, unmet, err := standalonetargets.RunTargets("посадка", targets,
		func(_, _ string) (int, string, error) { return 2, out, nil })
	require.NoError(t, err)
	require.Empty(t, findings, "метка, напечатанная самим рецептом, стала находкой")
	require.Len(t, unmet, 1, "третий исход рецепта потерян")
}

// rawGoTestFailure — вывод `go test -v`, позванного рецептом напрямую: вторая
// строка текста упавшей пробы — метка, первая на строке после отступа.
func rawGoTestFailure(failLine bool) string {
	var b strings.Builder
	b.WriteString("=== RUN   TestLedger\n")
	if failLine {
		b.WriteString("--- FAIL: TestLedger (0.00s)\n")
	}
	b.WriteString("    gate_test.go:42: первая строка отказа пробы\n")
	b.WriteString("        " + standalonetargets.UnmetPremiseMark + ": слова метки в тексте упавшей пробы\n")
	b.WriteString("FAIL\nmake: *** [Makefile:537: cla-check] Error 1\n")
	return b.String()
}

// TestRun_MarkInTheTextOfARawGoTestFailureIsAFinding — ось «go test в рецепте».
func TestRun_MarkInTheTextOfARawGoTestFailureIsAFinding(t *testing.T) {
	targets := []standalonetargets.Target{{Name: "cla-check", Desc: "подписи вкладов"}}
	findings, unmet, err := standalonetargets.RunTargets("посадка", targets,
		func(_, _ string) (int, string, error) { return 2, rawGoTestFailure(true), nil })
	require.NoError(t, err)
	require.Emptyf(t, unmet, "метка в тексте упавшей пробы go test подала красное третьим исходом:\n%v", unmet)
	require.Len(t, findings, 1)
	require.False(t, findings[0].Probes,
		"строка `--- FAIL:` объявила род «упали пробы модуля» — его метка принадлежит рецепту проб модуля")
}

// TestRun_IndentedMarkWithoutAFailLineIsStillUnmet — законный близнец: тот же
// вывод без строки `--- FAIL:`. Отличается одним фактом — признаком упавшей
// пробы; метка с отступом остаётся третьим исходом.
func TestRun_IndentedMarkWithoutAFailLineIsStillUnmet(t *testing.T) {
	targets := []standalonetargets.Target{{Name: "cla-check", Desc: "подписи вкладов"}}
	findings, unmet, err := standalonetargets.RunTargets("посадка", targets,
		func(_, _ string) (int, string, error) { return 2, rawGoTestFailure(false), nil })
	require.NoError(t, err)
	require.Empty(t, findings, "метка с отступом без упавшей пробы стала находкой")
	require.Len(t, unmet, 1)
}
