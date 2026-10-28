// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package standalonetargets_test

// probe_text_injection_test.go — находка «упали пробы модуля» несёт ТЕКСТ
// отказа каждой упавшей пробы, а не только её имя (задача #618, урок разбора
// PR #1069).
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

// TestProbeFailure_FindingCarriesTheRefusalText — инъекция: проба модуля падает
// с названным текстом; находка гейта обязана его нести.
func TestProbeFailure_FindingCarriesTheRefusalText(t *testing.T) {
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
	write("probe_test.go", fmt.Sprintf(`package probe

import "testing"

func TestRefuses(t *testing.T) { t.Fatalf(%q) }

func TestPassesWithANote(t *testing.T) { t.Log(%q) }
`, probeFailText, probePassNoise))
	write("scripts/test-standalone.sh", string(script))
	write("Makefile", "test-standalone:\n\t@bash scripts/test-standalone.sh $(ARGS)\n")

	targets := []standalonetargets.Target{{Name: "test-standalone", Desc: "пробы модуля"}}
	t.Setenv("GOWORK", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	findings, unmet, err := standalonetargets.RunTargets(dir, targets, makeRunner(t))
	require.NoError(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: цель не запустилась")
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
