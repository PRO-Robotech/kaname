// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package standalonetargets_test

// gate_test.go — гейт доказывается инъекцией в ОБЕ стороны и объявляет объём
// осмотренного.
//
// Каждая инъекция меняет РОВНО ОДИН факт против своего положительного близнеца:
// иначе неизвестно, какой из двух дал красное, и вердикт недействителен, хотя
// выглядит как обычный зелёный.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/gitenv"

	"github.com/PRO-Robotech/kaname/tools/standalonetargets"
)

// waivers — цели, которых гейт не зовёт, и НАЗВАННАЯ причина у каждой.
//
// Предмет у всех один по форме: ресурс, которого у пробы нет BY CONSTRUCTION.
// Это не отсрочка — такая цель не станет проверяемой оттого, что кто-то ею
// займётся: её предпосылку создаёт стенд, а не код. Запись, которой больше
// нечего покрывать, — находка (сверка ведомости в обе стороны ниже).
var waivers = []standalonetargets.Waiver{
	{Target: "lint", Reason: "зовёт golangci-lint — его на машине пробы может не быть вовсе, и это «не выполнилось», а не находка"},
	{Target: "docker", Reason: "зовёт демон сборки образов; посадку клона он не проверяет — образ собирается от того же дерева"},
	{Target: "migrate-up", Reason: "требует живую базу: предпосылку создаёт стенд, а не дерево"},
	{Target: "migrate-down", Reason: "требует живую базу: предпосылку создаёт стенд, а не дерево"},
	{Target: "migrate-status", Reason: "требует живую базу: предпосылку создаёт стенд, а не дерево"},
}

// ЗДЕСЬ СТОЯЛА ЗАПИСЬ ПРО `proto-install-plugins` — снята вместе со своей целью.
//
// Причина записи была верна и осталась верной: цель тянула плагины генерации из
// сети. Снята не она, а ПРЕДМЕТ — сама цель, вместе с `proto-vendor`,
// `proto-lint` и `proto-gen` (kacho#2413). Все четыре обслуживали полирепо-модель,
// где контракты службы лежали в `services/iam/proto/` и вендорились из соседнего
// `../kacho-corelib`. В монорепо нет ни того, ни другого: отслеживаемых файлов в
// `services/iam/proto` ноль, а генерация идёт из корневого `proto/` плагинами
// `go run` из `go.mod`, то есть в `$PATH` вообще не заглядывает.
//
// Запись пришлось снять ТЕМ ЖЕ изменением, и это не аккуратность, а механизм:
// ведомость сверяется в обе стороны (`census.StaleWaiv` ниже), поэтому waiver,
// переживший свою цель, роняет прогон. Так и задумано — послабление живёт, пока у
// него есть предмет.

// ЗДЕСЬ СТОЯЛА ЗАПИСЬ ПРО `cla-check` — предмета у неё нет, и её причина была ЛОЖНА.
//
// Причина гласила: «фикстура — распакованный состав коммита ВНЕ всякого
// репозитория (AssertOutsideAnyRepository выше): истории у неё нет by
// construction». Обе половины неверны о ТОЙ ЖЕ функции, что стоит ниже:
// `AssertOutsideAnyRepository` требует, чтобы каталог не лежал ВНУТРИ чужого
// дерева, после чего фикстура сама делает `git init` и коммит. То есть история у
// неё ЕСТЬ — ровно один коммит, и он не история домена.
//
// Прощение при этом не работало ни дня: `cla-check` — тонкая обёртка над тем же
// `go test ./tools/clagate/`, который фикстура и так зовёт целью
// `test-standalone`. Запись прощала ИМЯ, а содержимое исполнялось соседним
// путём — и именно оттуда пришло красное: задача продукта #2239 закрыла нерезолв
// области, и вместе с ним пропал побочный признак, по которому третий исход
// опознавался.
//
// Теперь третий исход опознаётся ПРЕДМЕТОМ (`clagate.Classify`), цель в фикстуре
// проходит, и запись снята: послабление живёт, пока у него есть предмет.

// TestStandaloneTargetsWorkInAStandaloneClone — боевой прогон: каждая цель,
// которую рецепт НЕ пометил `[монорепо]`, зовётся в самостоятельном клоне.
//
// Клон собирается из состава КОММИТА, а не рабочего каталога: арендатору едет
// то, что отслеживается деревом, и судить надо именно его.
func TestStandaloneTargetsWorkInAStandaloneClone(t *testing.T) {
	if testing.Short() {
		t.Skip("собирает клон и зовёт цели сборки — прогон интеграционного порядка")
	}

	wd, err := os.Getwd()
	require.NoError(t, err)
	moduleRoot, err := standalonetargets.ModuleRootFrom(wd)
	require.NoError(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не установлен")

	raw, err := os.ReadFile(filepath.Join(moduleRoot, "Makefile"))
	require.NoError(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: рецепт модуля не прочитан")

	targets := standalonetargets.ParseTargets(raw)
	judged, census := standalonetargets.Judged(targets, waivers)

	clone := buildStandaloneClone(t, moduleRoot)
	census.Posture = clone
	t.Log(census.String())

	// Пустой обход — отказ, а не успех: «ноль находок» обязано быть отличимо от
	// «ноль прочитанного».
	require.NotEmpty(t, targets,
		"в рецепте не прочитано ни одной строки объявления цели — обход беспредметен, вердикта нет")
	require.NotEmpty(t, judged,
		"судить нечего: каждая цель либо помечена %s, либо прощена ведомостью — "+
			"перечень перестал обещать арендатору что-либо, и это решение, а не зелёное",
		"[монорепо]")

	// Ведомость сверяется в обе стороны: запись без предмета переживает свою цель
	// и достанется следующей, случайно совпавшей по имени.
	require.Empty(t, census.StaleWaiv,
		"записи ведомости, которым больше нечего прощать: %v — послабление живёт, пока у него есть предмет",
		census.StaleWaiv)

	findings, err := standalonetargets.RunTargets(clone, judged, makeRunner(t))
	require.NoError(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ")
	for _, f := range findings {
		t.Errorf("%s\n  посадка: %s", f, clone)
	}
}

// buildStandaloneClone — самостоятельная посадка модуля во временном каталоге.
//
// Отказ здесь — «проверка НЕ ИСПОЛНЯЛАСЬ», а не находка: гейт, не собравший
// клон, о целях не утверждает ничего и не вправе выглядеть успехом.
func buildStandaloneClone(t *testing.T, moduleRoot string) string {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, standalonetargets.AssertOutsideAnyRepository(dir),
		"проверка НЕ ИСПОЛНЯЛАСЬ: фикстуру негде собрать")

	// Путь модуля ОТНОСИТЕЛЬНО корня дерева: в монорепо это services/iam, у
	// арендатора — точка. Спрашивается у git, а не складывается из `..`: число
	// уровней верно ровно для одной посадки, а гейт обязан работать в обеих.
	top, err := gitenv.Command(moduleRoot, "rev-parse", "--show-toplevel").Output()
	require.NoError(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: дерево модуля не установлено")
	treeRoot := strings.TrimSpace(string(top))
	rel, err := filepath.Rel(treeRoot, moduleRoot)
	require.NoError(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: модуль не сводится под корень дерева")

	treeish := "HEAD"
	if rel != "." {
		treeish = "HEAD:" + filepath.ToSlash(rel)
	}

	// Выгрузка идёт ОТ КОРНЯ ДЕРЕВА, а не из каталога модуля, и это не стиль:
	// путь в `<tree-ish>:<путь>` git разрешает ОТНОСИТЕЛЬНО рабочего каталога,
	// поэтому та же строка, поданная из services/iam, ищет services/iam/services/iam
	// и выгружает НОЛЬ файлов — молча, кодом 0. Клон вышел бы пустым, а гейт
	// объявил бы «судить нечего» вместо вердикта о целях.
	tar := exec.Command("tar", "-x", "-C", dir)
	ar := gitenv.Command(treeRoot, "archive", "--format=tar", treeish)
	pipe, err := ar.StdoutPipe()
	require.NoError(t, err)
	tar.Stdin = pipe
	require.NoError(t, tar.Start())
	require.NoError(t, ar.Run(), "проверка НЕ ИСПОЛНЯЛАСЬ: состав коммита модуля не выгружен")
	require.NoError(t, tar.Wait(), "проверка НЕ ИСПОЛНЯЛАСЬ: состав коммита модуля не распакован")

	// Пустая выгрузка — отдельный исход, и назвать его надо ЗДЕСЬ. Обе команды
	// выше выходят кодом 0 на пустом дереве, поэтому без этой проверки гейт
	// поехал бы дальше и упал позже, назвав виновником невиновный шаг.
	entries, rerr := os.ReadDir(dir)
	require.NoError(t, rerr)
	require.NotEmptyf(t, entries,
		"проверка НЕ ИСПОЛНЯЛАСЬ: выгрузка состава коммита (%s из %s) дала ноль файлов", treeish, treeRoot)

	// Клон обязан быть репозиторием: цели спрашивают у git и корень дерева, и
	// состав коммита. Распакованный архив дал бы им «проверка не исполнялась» —
	// то есть гейт мерил бы отсутствие git, а не посадку.
	for _, args := range [][]string{
		{"init", "-q", "."},
		{"-c", "user.email=probe@example.invalid", "-c", "user.name=probe", "add", "-A"},
		{"-c", "user.email=probe@example.invalid", "-c", "user.name=probe", "commit", "-q", "-m", "самостоятельная посадка модуля"},
	} {
		out, err := gitenv.Command(dir, args...).CombinedOutput()
		require.NoErrorf(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: git %v в фикстуре: %s", args, out)
	}

	n, err := gitenv.Command(dir, "ls-files").Output()
	require.NoError(t, err)
	require.NotEmpty(t, strings.TrimSpace(string(n)),
		"проверка НЕ ИСПОЛНЯЛАСЬ: в собранном клоне ноль отслеживаемых файлов")

	return dir
}

// makeRunner — единственное место, где гейт трогает `make`. Отказ ЗАПУСКА
// («make не нашёлся») отделён от отказа ЦЕЛИ: первый — «проверка не
// исполнялась», второй — находка, и смешивать их значило бы отчитываться о
// продукте отсутствием инструмента.
func makeRunner(t *testing.T) func(dir, target string) (int, string, error) {
	t.Helper()
	return func(dir, target string) (int, string, error) {
		cmd := exec.Command("make", target)
		cmd.Dir = dir
		cmd.Env = append(gitenv.Env(), "GOFLAGS=-mod=mod")
		start := time.Now()
		out, err := cmd.CombinedOutput()
		t.Logf("цель %s: %s, вывода %d байт", target, time.Since(start).Round(time.Millisecond), len(out))
		if err == nil {
			return 0, string(out), nil
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), string(out), nil
		}
		return 0, "", err
	}
}
