// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// process_knob_names_test.go — ДЕРЖАТЕЛЬ оси «ручки» условия «имя платформы
// не остаётся на поверхности службы» (kacho#2076, предикат C, п. 3): ни один
// двоичный файл службы не читает переменной окружения, названной именем
// платформы.
//
// Почему судится то, что линкуется, а не текст дерева, и чего судья не судит —
// в шапке `process_knob_names.go`; здесь не пересказывается. Способность
// упасть и смолчать доказана инъекцией — `process_knob_names_injection_test.go`.
//
// Корпус — НАСТОЯЩИЙ граф сборки: `go list -deps ./cmd/...`, сужённый до
// пакетов этого модуля. Перечень двоичных файлов выводится из каталога `cmd/`,
// а не выписывается: выписанный отстал бы от каталога молча.
package supplyhygiene

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// linkedPackageDirs — каталоги пакетов ЭТОГО модуля, линкуемых в двоичные
// файлы `cmd/...`.
func linkedPackageDirs(t *testing.T, root string) (map[string]string, string) {
	t.Helper()
	modCmd := exec.Command("go", "list", "-m")
	modCmd.Dir = root
	modOut, err := modCmd.Output()
	require.NoError(t, err, "go list -m в %s", root)
	module := strings.TrimSpace(string(modOut))
	require.NotEmpty(t, module)

	cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}} {{.Dir}}", "./cmd/...")
	cmd.Dir = root
	out, err := cmd.Output()
	require.NoError(t, err, "go list -deps ./cmd/... в %s", root)

	dirs := map[string]string{}
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || !strings.HasPrefix(fields[0], module+"/") && fields[0] != module {
			continue
		}
		dirs[fields[0]] = fields[1]
	}
	return dirs, module
}

// linkedSources — не-тестовые исходники Go всех пакетов модуля, линкуемых в
// двоичные файлы; ключ — путь от корня службы.
func linkedSources(t *testing.T) (map[string][]byte, string, int) {
	t.Helper()
	root, err := filepath.Abs(serviceRoot)
	require.NoError(t, err)

	dirs, module := linkedPackageDirs(t, root)
	require.NotEmpty(t, dirs, "граф сборки пуст: ни один пакет модуля не линкуется в двоичные файлы — вердикт беспредметен")

	sources := map[string][]byte{}
	for pkg, dir := range dirs {
		entries, readErr := os.ReadDir(dir)
		require.NoError(t, readErr, "пакет %s", pkg)
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			abs := filepath.Join(dir, name)
			body, rerr := os.ReadFile(abs) // #nosec G304 -- путь взят у графа сборки
			require.NoError(t, rerr)
			rel, relErr := filepath.Rel(root, abs)
			require.NoError(t, relErr)
			sources[filepath.ToSlash(rel)] = body
		}
	}
	return sources, module, len(dirs)
}

func TestServiceProcessReadsNoKnobNamedForThePlatform(t *testing.T) {
	sources, module, packages := linkedSources(t)

	census, findings := JudgeProcessKnobNames(sources)
	t.Logf("перепись: модуль %s · пакетов в двоичных файлах %d · файлов Go разобрано %d · "+
		"литералов %d · формы имени переменной %d · не разобрано %d",
		module, packages, census.Files, census.Literals, census.EnvShaped, len(census.Unparsed))
	require.NotZero(t, census.Files, "файлов не разобрано ни одного — «ноль находок» означало бы «ноль прочитанного»")
	require.NotZero(t, census.EnvShaped, "литералов формы имени переменной ноль: процесс читает ручки, и распознаватель перестал их видеть")
	require.Empty(t, census.Unparsed, "файлы, которых разбор не прочёл: %v", census.Unparsed)
	for _, f := range findings {
		t.Error(fmt.Sprint(f))
	}
}

// TestServiceProcessDeclaresNoTrustDomainLiteral — WIRE-4-03: домен доверия,
// который служба принимает, не объявлен ни одним литералом кода двоичных
// файлов; он приходит настройкой, и объявляет его тот, кто ставит.
func TestServiceProcessDeclaresNoTrustDomainLiteral(t *testing.T) {
	sources, module, packages := linkedSources(t)

	census, findings := JudgeProcessTrustDomainLiterals(sources)
	t.Logf("перепись: модуль %s · пакетов в двоичных файлах %d · файлов Go разобрано %d · "+
		"литералов %d · не разобрано %d",
		module, packages, census.Files, census.Literals, len(census.Unparsed))
	require.NotZero(t, census.Literals, "литералов осмотрено ноль — «ноль находок» означало бы «ноль прочитанного»")
	require.Empty(t, census.Unparsed, "файлы, которых разбор не прочёл: %v", census.Unparsed)
	for _, f := range findings {
		t.Errorf("%s:%d: код объявляет SPIFFE-имя литералом %q — домен доверия принадлежит "+
			"настройке установки (KANAME_AUTHN__TRUST_DOMAIN), а не коду", f.File, f.Line, f.Name)
	}
}
