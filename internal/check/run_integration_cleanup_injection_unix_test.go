// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

// run_integration_cleanup_injection_unix_test.go — ПРОБА СЛЕДОВ СПОСОБНА
// УПАСТЬ И СПОСОБНА СМОЛЧАТЬ (задача PRO-Robotech/kaname#671).
//
// Инъекция идёт НАСТОЯЩИМ входом: сценарий читается из дерева, и дефект
// вносится в его копию — по одному факту за раз. Каждой половине «краснеет»
// отвечает законный близнец той же формы, который обязан молчать; на дереве
// как есть находок ноль — это утверждает несущая проба.
package check_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// injectRunIntegration — копия сценария с одной заменой; замена обязана
// найтись, иначе инъекция беспредметна.
func injectRunIntegration(t *testing.T, raw, from, to string) string {
	t.Helper()
	require.Containsf(t, raw, from, "инъекция беспредметна: в сценарии нет %q", from)
	return strings.Replace(raw, from, to, 1)
}

func TestRunIntegrationCleanupProbeCanFail(t *testing.T) {
	t.Parallel()
	raw := runIntegrationSource(t)

	// ПРЕЖНИЙ ДЕФЕКТ, возвращённый дословно: ловушка журнала заменяет общую
	// и снимает только то, что перечислила.
	t.Run("возвращена прежняя ловушка журнала", func(t *testing.T) {
		t.Parallel()
		got, _ := auditRunIntegration(t, injectRunIntegration(t, raw,
			`log="$work/go-test.log"`,
			`log="$(mktemp)"; trap 'rm -f "$list_err" "$log"' EXIT`))
		require.NotEmpty(t, got)
		require.Contains(t, strings.Join(got, "\n"), "go test зелёный: во временном каталоге остались следы")
		require.Contains(t, strings.Join(got, "\n"), "прерывание SIGTERM во время go test: во временном каталоге остались следы")
	})

	// НОВЫЙ ДЕФЕКТ того же класса: поздняя ловушка, не знающая каталога.
	t.Run("поздняя ловушка заменяет общую", func(t *testing.T) {
		t.Parallel()
		got, _ := auditRunIntegration(t, injectRunIntegration(t, raw,
			`log="$work/go-test.log"`,
			`log="$work/go-test.log"; trap 'echo снято' EXIT`))
		require.Contains(t, strings.Join(got, "\n"), "go test красный: во временном каталоге остались следы")
	})

	// Временный файл заведён мимо общего каталога — снятие его не знает.
	t.Run("временный файл мимо общего каталога", func(t *testing.T) {
		t.Parallel()
		got, _ := auditRunIntegration(t, injectRunIntegration(t, raw,
			`imports_err="$work/imports.err"`,
			`imports_err="$(mktemp)"`))
		joined := strings.Join(got, "\n")
		require.Contains(t, joined, "разбор импортов сорвался: во временном каталоге остались следы")
		require.Contains(t, joined, "прерывание SIGHUP во время go test: во временном каталоге остались следы")
	})

	// Без своей ловушки SIGINT прерванный прогон уходит в классификатор.
	t.Run("ловушка SIGINT снята — прерванный прогон выходит зелёным", func(t *testing.T) {
		t.Parallel()
		got, _ := auditRunIntegration(t, injectRunIntegration(t, raw, "trap 'exit 130' INT\n", ""))
		require.Equal(t, []string{"прерывание SIGINT во время go test: код выхода 0, ожидался 130"}, got)
	})
}

// TestRunIntegrationCleanupProbeCanStaySilent — ЗАКОННЫЕ БЛИЗНЕЦЫ тех же форм.
// Без них проба запрещала бы слово `trap` и `mktemp`, а не потерю снятия.
func TestRunIntegrationCleanupProbeCanStaySilent(t *testing.T) {
	t.Parallel()
	raw := runIntegrationSource(t)

	t.Run("поздняя ловушка, снимающая каталог", func(t *testing.T) {
		t.Parallel()
		got, _ := auditRunIntegration(t, injectRunIntegration(t, raw,
			`log="$work/go-test.log"`,
			`log="$work/go-test.log"; trap 'rm -rf -- "$work"; echo снято' EXIT`))
		require.Empty(t, got)
	})

	t.Run("временный файл заведён mktemp внутри общего каталога", func(t *testing.T) {
		t.Parallel()
		got, _ := auditRunIntegration(t, injectRunIntegration(t, raw,
			`imports_err="$work/imports.err"`,
			`imports_err="$(mktemp -p "$work")"`))
		require.Empty(t, got)
	})
}
