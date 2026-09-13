// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// trunk_verdict_register_test.go — ГЕЙТ и его ИНЪЕКЦИЯ: перечень «что не
// переносится со слияния на ствол» полон, его координаты резолвятся, и каждый
// процесс ствола в нём назван (задача PRO-Robotech/kaname#62, предикат 3).
//
// Предмет и граница гейта — в шапке `trunk_verdict_register.go`; здесь они не
// пересказываются.
package check_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// trunkJobsAndProcesses — задания дерева (имя → процесс) и отображаемые имена
// процессов ствола. ВЫВОДЯТСЯ обходом, а не выписываются.
func trunkJobsAndProcesses(t *testing.T) (map[string]string, []string) {
	t.Helper()
	jobs := map[string]string{}
	var procs []string
	for name, raw := range trunkCorpusSource(t) {
		var doc struct {
			Name string               `yaml:"name"`
			Jobs map[string]yaml.Node `yaml:"jobs"`
		}
		require.NoError(t, yaml.Unmarshal([]byte(raw), &doc), name)
		onTrunk, title, err := check.PushesToTrunk(raw)
		require.NoError(t, err, name)
		if !onTrunk {
			continue
		}
		procs = append(procs, title)
		for j := range doc.Jobs {
			jobs[j] = title
		}
	}
	require.NotEmpty(t, jobs, "заданий выведено ноль — резолвить координаты не с чем")
	require.GreaterOrEqual(t, len(procs), 2, "процессов ствола меньше двух — свойство вырождено")
	return jobs, procs
}

func registerSource(t *testing.T) string {
	t.Helper()
	root, prefix := platformtree.RequireCorpus(t)
	if prefix != "" {
		root = filepath.Join(root, filepath.FromSlash(prefix))
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(check.TrunkRegisterRel))) // #nosec G304 -- координата объявлена постоянной
	require.NoErrorf(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: %s не прочитан — «ноль находок» "+
		"означало бы «ноль прочитанного»", check.TrunkRegisterRel)
	return string(raw)
}

// TestTrunkRegisterNamesAProducerForEveryDivergence — НЕСУЩЕЕ утверждение и
// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ инъекции ниже.
func TestTrunkRegisterNamesAProducerForEveryDivergence(t *testing.T) {
	t.Parallel()

	jobs, procs := trunkJobsAndProcesses(t)
	findings, census, err := check.AuditTrunkRegister(registerSource(t), jobs, procs)
	require.NoError(t, err)

	t.Logf("ОБЪЁМ ОСМОТРЕННОГО: %s · находок %d", census, len(findings))

	require.GreaterOrEqual(t, census.Rows, 5,
		"перечень короче пяти строк: расхождений между слиянием и стволом измерено больше")
	require.Equal(t, census.Rows, census.Complete,
		"строка без производителя есть обещание — ровно тот класс, который #62 закрывает")
	require.Equal(t, census.ProcessesOnTrunk, census.ProcessesNamed)
	require.GreaterOrEqual(t, census.JobsResolved, 5,
		"координат заданий резолвится меньше пяти — перечень называет предмет прозой, "+
			"и его устаревание будет невидимо")

	for _, f := range findings {
		t.Error(f)
	}
}

// TestTrunkRegisterGateCanFail — половина «краснеет», по оси на подпробу.
// Инъекция идёт НАСТОЯЩИМ входом и меняет один факт за раз.
func TestTrunkRegisterGateCanFail(t *testing.T) {
	t.Parallel()

	jobs, procs := trunkJobsAndProcesses(t)
	raw := registerSource(t)

	audit := func(t *testing.T, in string) []string {
		t.Helper()
		got, _, err := check.AuditTrunkRegister(in, jobs, procs)
		require.NoError(t, err, "инъекция доказывала бы разбор, а не гейт")
		return got
	}

	t.Run("строка потеряла производителя — обещание вместо проверки", func(t *testing.T) {
		// Один факт: у одной строки опустела третья колонка.
		const row = "| публикация образа | на запросе слияния сборка идёт **без** `--push`: полоса публикации не исполняется |"
		require.Contains(t, raw, row, "фикстура инъекции устарела вместе с перечнем")
		i := strings.Index(raw, row)
		j := strings.Index(raw[i:], "\n") + i
		got := audit(t, raw[:i]+row+" |"+raw[j:])
		require.Len(t, got, 1)
		require.Contains(t, got[0], "ЧЕМ свойство судится после посадки")
	})

	t.Run("координата пережила своё задание", func(t *testing.T) {
		// Один факт: во ВТОРОЙ колонке таблицы контекстов — имя снятого задания.
		const cell = "| `build` | ci |"
		require.Contains(t, raw, cell, "фикстура инъекции устарела вместе с перечнем")
		got := audit(t, strings.Replace(raw, cell, "| `buildretired` | ci |", 1))
		require.Len(t, got, 1)
		require.Contains(t, got[0], "которого в дереве нет")
	})

	// ЗАКОННЫЙ БЛИЗНЕЦ распознавателя: имя, названное ПРОЗОЙ и заданием не
	// являющееся, находкой быть не должно. Первая редакция судила по ФОРМЕ имени
	// и объявляла несуществующими заданиями флаги, ключи объявления и имя
	// процесса — 7 ложных находок из 23 распознанных.
	t.Run("имя в прозе заданием не объявляется", func(t *testing.T) {
		got := audit(t, strings.Replace(raw, "`--push`", "`--pushretired`", 1))
		require.Empty(t, got, "имя из прозы объявлено несуществующим заданием")
	})

	t.Run("процесс ствола в перечне не назван", func(t *testing.T) {
		got := audit(t, strings.ReplaceAll(raw, "e2e-newman", "нечто"))
		require.NotEmpty(t, got)
		require.Contains(t, strings.Join(got, "\n"), "в перечне не назван")
	})

	t.Run("перечень пуст — вердикт беспредметен", func(t *testing.T) {
		_, _, err := check.AuditTrunkRegister("   ", jobs, procs)
		require.Error(t, err)
	})

	t.Run("заданий дерева не подано — резолвить не с чем", func(t *testing.T) {
		_, _, err := check.AuditTrunkRegister(raw, map[string]string{}, procs)
		require.Error(t, err, "пустой набор заданий принят: «все резолвятся» стало бы "+
			"«ни одной не проверили»")
	})

	// ЗАКОННЫЙ БЛИЗНЕЦ: имя в кавычках, заданием НЕ являющееся (файл, ручка,
	// флаг), находкой быть не должно — иначе гейт запрещал бы перечню называть
	// что-либо, кроме заданий.
	t.Run("строка перечня с координатами в прозе — не находка", func(t *testing.T) {
		got := audit(t, raw+"\n\n| свойство | причина | `.github/scripts/x.sh` и `KANAME_KNOB` |\n")
		require.Empty(t, got, "координата, не являющаяся заданием, объявлена несуществующим заданием")
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// СВЕРКА СПИСАННОГО С ЖИВЫМ: обязательные контексты живут в НАСТРОЙКАХ ВЕТКИ,
// а не в дереве, поэтому перечень их копирует — и копия стареет молча.
//
// Измерение СЕТЕВОЕ и потому идёт по ручке. Перепись называет, СВЕРЯЛА ли она:
// «сверено 0» никогда не должно читаться как «сверено» — ровно тот класс,
// который весь этот файл и закрывает.
const branchProtectionKnob = "KANAME_BRANCH_PROTECTION_CHECK"

func TestDeclaredRequiredContextsMatchTheBranch(t *testing.T) {
	t.Parallel()

	_, procs := trunkJobsAndProcesses(t)
	declared := check.DeclaredContexts(registerSource(t), procs)
	require.GreaterOrEqual(t, len(declared), 5,
		"перечень объявляет меньше пяти обязательных контекстов — сверять почти нечего")

	if os.Getenv(branchProtectionKnob) != "1" {
		t.Logf("ОБЪЁМ ОСМОТРЕННОГО: объявлено контекстов %d · сверено с веткой 0 "+
			"(ручка %s не выставлена — это «не спрашивали», а НЕ «сошлось»)",
			len(declared), branchProtectionKnob)
		t.Skip("сверка с настройками ветки — сетевая, идёт по ручке")
	}

	repo := os.Getenv("KANAME_REPO")
	if repo == "" {
		repo = "PRO-Robotech/kaname"
	}
	out, err := exec.Command("gh", "api",
		"repos/"+repo+"/branches/main/protection",
		"--jq", ".required_status_checks.contexts[]").Output() // #nosec G204 -- имя репозитория из ручки, не из ввода
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: настройки ветки не прочитаны: %v — это третий "+
			"исход, а не «сошлось»", err)
	}
	var live []string
	for _, ln := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			live = append(live, ln)
		}
	}
	require.NotEmpty(t, live, "у ветки ноль обязательных контекстов — вердикт беспредметен")

	sort.Strings(live)
	t.Logf("ОБЪЁМ ОСМОТРЕННОГО: объявлено контекстов %d · у ветки %d · сверено %d",
		len(declared), len(live), len(live))
	require.ElementsMatch(t, live, declared,
		"перечень разошёлся с настройками ветки: он объявляет то, чего ветка не требует, "+
			"либо молчит о том, что она требует")
}
