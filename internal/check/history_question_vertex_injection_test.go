// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// history_question_vertex_injection_test.go — ГЕЙТ СПОСОБЕН УПАСТЬ И СПОСОБЕН
// СМОЛЧАТЬ (задача PRO-Robotech/kaname#63).
//
// # ИНЪЕКЦИЯ ИДЁТ ФОРМОЙ ИЗ ДЕРЕВА, А НЕ СИНТЕТИКОЙ О СЕБЕ
//
// Возвращаемый дефект записан ДОСЛОВНО тем вызовом, который в дереве стоит
// (`seed_identity_census_test.go`), а законный близнец отличается от него РОВНО
// ОДНИМ фактом — названной вершиной. Синтетический литерал доказывал бы, что
// разбор понимает синтетику.
//
// # ДВЕ ПОЛОВИНЫ, И ВТОРАЯ НЕ МЕНЕЕ ВАЖНА
//
// Половина «краснеет» проверяется по каждой оси отдельно: вершина рабочая ·
// вершина не названа · запись без довода · число вызовов разошлось · записи
// нечего прощать. Половина «молчит» — на стволе и на ПРОЗЕ: корпус этого дерева
// объясняет свои проверки теми же словами, и гейт, краснеющий на объяснении,
// был бы снят первым же ложным срабатыванием.
//
// # ДОВОД, УТВЕРЖДАЮЩИЙ СВОЙСТВО СХЛОПЫВАНИЯ, ЗАМЕРЕН, А НЕ ОБЪЯВЛЕН
//
// Самая длинная запись ведомости (`acceptance_edit_after_verdict.go#log`) стоит
// на утверждении о ПОВЕДЕНИИ git: схлопывание переносит оба операнда сравнения
// одним коммитом, поэтому вердикт сохраняется. Утверждение проверяется опытом
// внизу файла — на синтетическом репозитории, где полоса схлопывается в ствол.
// Довод, которого никто не мерил, есть мнение с координатой.
package check_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/gitenv"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// headVertexCallFromTheTree — форма, стоящая в дереве ДОСЛОВНО.
const headVertexCallFromTheTree = `cmd := exec.Command("git", "-C", root, "merge-base", "--is-ancestor", rev, "HEAD")`

// trunkVertexTwin — ЗАКОННЫЙ БЛИЗНЕЦ: тот же вызов, названа другая вершина.
const trunkVertexTwin = `cmd := exec.Command("git", "-C", root, "merge-base", "--is-ancestor", rev, "origin/main")`

// unnamedVertexCallFromTheTree — форма, у которой вершина приходит переменной.
const unnamedVertexCallFromTheTree = `cmd := exec.Command("git", "-C", root, "merge-base", "--is-ancestor", rev, trunk)`

// goSource собирает файл Go вокруг одной строки тела.
func goSource(body string) []byte {
	return []byte("package p\n\nimport \"os/exec\"\n\nfunc f(root, rev, trunk string) {\n\t" +
		body + "\n\t_ = cmd\n}\n")
}

func scanOne(t *testing.T, rel string, src []byte) ([]check.HistoryQuestion, check.HistoryCensus) {
	t.Helper()
	qs, c := check.ScanHistoryQuestions(map[string][]byte{rel: src}, historyTrunkRefs)
	require.Zerof(t, len(c.GoUnparsed), "файл %s не разобран — инъекция доказывала бы разбор, а не гейт", rel)
	return qs, c
}

// TestHistoryVertexGateCanFail — ПОЛОВИНА «КРАСНЕЕТ», по оси на подпробу.
func TestHistoryVertexGateCanFail(t *testing.T) {
	t.Parallel()

	t.Run("вершина названа рабочей — находка с координатой", func(t *testing.T) {
		qs, c := scanOne(t, "internal/x/a_test.go", goSource(headVertexCallFromTheTree))
		require.Equal(t, 1, c.Head, "разбор не увидел рабочей вершины в форме, стоящей в дереве")
		findings, applied, stale := judgeHistoryVertices(qs, map[string]vertexWaiver{})
		require.Empty(t, stale)
		require.Zero(t, applied)
		require.Len(t, findings, 1)
		require.Contains(t, findings[0], "internal/x/a_test.go:")
		require.Contains(t, findings[0], "рабочая вершина")
		require.Contains(t, findings[0], "merge-base")
	})

	t.Run("вершина не названа литералом — тоже находка", func(t *testing.T) {
		qs, c := scanOne(t, "internal/x/b.go", goSource(unnamedVertexCallFromTheTree))
		require.Equal(t, 1, c.Unnamed)
		findings, _, _ := judgeHistoryVertices(qs, map[string]vertexWaiver{})
		require.Len(t, findings, 1)
		require.Contains(t, findings[0], "не названа литералом")
	})

	t.Run("запись ведомости без довода — находка", func(t *testing.T) {
		qs, _ := scanOne(t, "internal/x/a_test.go", goSource(headVertexCallFromTheTree))
		findings, applied, _ := judgeHistoryVertices(qs, map[string]vertexWaiver{
			"internal/x/a_test.go#merge-base": {Calls: 1, Why: "   "},
		})
		require.Zero(t, applied)
		require.Len(t, findings, 1)
		require.Contains(t, findings[0], "БЕЗ ДОВОДА")
	})

	t.Run("число вызовов разошлось — адъюдикация устарела", func(t *testing.T) {
		src := goSource(headVertexCallFromTheTree + "\n\t" +
			strings.Replace(headVertexCallFromTheTree, "cmd :=", "cmd2 :=", 1) + "\n\t_ = cmd2")
		qs, c := scanOne(t, "internal/x/a_test.go", src)
		require.Equal(t, 2, c.Head)
		findings, applied, _ := judgeHistoryVertices(qs, map[string]vertexWaiver{
			"internal/x/a_test.go#merge-base": {Calls: 1, Why: "довод"},
		})
		require.Zero(t, applied)
		require.Len(t, findings, 1)
		require.Contains(t, findings[0], "прощает 1 вызов(ов), а их в файле 2")
	})

	t.Run("записи нечего прощать — САМОИСТЕЧЕНИЕ", func(t *testing.T) {
		qs, _ := scanOne(t, "internal/x/a_test.go", goSource(trunkVertexTwin))
		findings, _, stale := judgeHistoryVertices(qs, map[string]vertexWaiver{
			"internal/x/a_test.go#merge-base": {Calls: 1, Why: "довод пережил свой предмет"},
		})
		require.Empty(t, findings)
		require.Equal(t, []string{"internal/x/a_test.go#merge-base"}, stale)
	})

	t.Run("форма оболочки — находка", func(t *testing.T) {
		src := []byte("#!/usr/bin/env bash\ngit -C \"$dir\" rev-list --count HEAD\n")
		qs, c := scanOne(t, "tools/x.sh", src)
		require.Equal(t, 1, c.Head, "разбор не прочитал вызов в форме оболочки")
		findings, _, _ := judgeHistoryVertices(qs, map[string]vertexWaiver{})
		require.Len(t, findings, 1)
		require.Contains(t, findings[0], "tools/x.sh:2")
	})

	t.Run("помощник, переадресующий запускателю, читается как вызов", func(t *testing.T) {
		src := []byte("package p\n\nimport \"github.com/PRO-Robotech/corelib/gitenv\"\n\n" +
			"func f(root string) {\n" +
			"\tgit := func(args ...string) { _, _ = gitenv.Command(root, args...).Output() }\n" +
			"\tgit(\"merge-base\", \"--is-ancestor\", \"abc\", \"HEAD\")\n}\n")
		qs, c := scanOne(t, "internal/x/c_test.go", src)
		require.Equalf(t, 1, c.Head, "помощник-замыкание не опознан запускателем: %v", qs)
		findings, _, _ := judgeHistoryVertices(qs, map[string]vertexWaiver{})
		require.Len(t, findings, 1)
	})

	t.Run("форма python — находка", func(t *testing.T) {
		src := []byte("import subprocess\nout = subprocess.run([\"git\", \"-C\", root, \"rev-list\", \"--count\", \"HEAD\"])\n")
		qs, c := scanOne(t, "tools/x.py", src)
		require.Equal(t, 1, c.Head, "разбор не прочитал вызов в форме списка python")
		findings, _, _ := judgeHistoryVertices(qs, map[string]vertexWaiver{})
		require.Len(t, findings, 1)
		require.Contains(t, findings[0], "tools/x.py:2")
	})
}

// TestHistoryVertexGateCanStaySilent — ПОЛОВИНА «МОЛЧИТ».
func TestHistoryVertexGateCanStaySilent(t *testing.T) {
	t.Parallel()

	t.Run("вершина — ствол: вопрос задан верно", func(t *testing.T) {
		qs, c := scanOne(t, "internal/x/a_test.go", goSource(trunkVertexTwin))
		require.Equal(t, 1, c.Trunk, "ствол не опознан — тогда молчание гейта ничего не стоит")
		require.Zero(t, c.Head)
		findings, applied, stale := judgeHistoryVertices(qs, map[string]vertexWaiver{})
		require.Empty(t, findings)
		require.Zero(t, applied, "вопрос стволу ведомости не требует")
		require.Empty(t, stale)
	})

	t.Run("довод записан — вопрос прощён и СОСЧИТАН", func(t *testing.T) {
		qs, _ := scanOne(t, "internal/x/a_test.go", goSource(headVertexCallFromTheTree))
		findings, applied, stale := judgeHistoryVertices(qs, map[string]vertexWaiver{
			"internal/x/a_test.go#merge-base": {Calls: 1, Why: "предмет — само дерево прогона"},
		})
		require.Empty(t, findings)
		require.Equal(t, 1, applied)
		require.Empty(t, stale)
	})

	// ПРОЗА — ГЛАВНАЯ ОСЬ МОЛЧАНИЯ. Шапки этого корпуса поминают и `merge-base`,
	// и `HEAD`; проверка, краснеющая на собственном объяснении, есть ровно тот
	// класс, который здесь и ловится.
	t.Run("проза Go — комментарий и строковый литерал", func(t *testing.T) {
		src := []byte("package p\n\n" +
			"// git merge-base --is-ancestor <ревизия> HEAD — так спрашивать НЕЛЬЗЯ.\n" +
			"const why = \"git merge-base --is-ancestor rev HEAD\"\n\n" +
			"func f() string { return why }\n")
		qs, c := scanOne(t, "internal/x/doc.go", src)
		require.Zerof(t, c.Questions, "проза Go прочитана как вызов: %v", qs)
	})

	t.Run("проза оболочки — комментарий и строка вывода", func(t *testing.T) {
		src := []byte("#!/usr/bin/env bash\n" +
			"# предикат: git merge-base --is-ancestor \"$rev\" HEAD\n" +
			"echo \"проверить так: git rev-list --count HEAD\"\n")
		qs, c := scanOne(t, "tools/x.sh", src)
		require.Zerof(t, c.Questions, "проза оболочки прочитана как вызов: %v", qs)
		// Две: строка запуска и строка комментария. Величина печатается гейтом
		// затем, чтобы «проза не сработала» было ЗАМЕРОМ, а не обещанием.
		require.Equal(t, 2, c.LinesStripped, "снятые строки комментария не сосчитаны")
	})

	// ФОРМА, СТОЯВШАЯ В ДЕРЕВЕ И ДАВШАЯ ЧЕТЫРЕ ЛОЖНЫХ НАХОДКИ ДО ФОРМЫ ВЫЗОВА.
	t.Run("проза python — предикат в строковом литерале", func(t *testing.T) {
		src := []byte("red = (\"предикат: `git log --oneline --all -- tests/x | wc -l` → 0\")\n" +
			"if \"git\" not in low or \"log\" not in low:\n    pass\n")
		qs, c := scanOne(t, "tools/x.py", src)
		require.Zerof(t, c.Questions, "проза python прочитана как вызов: %v", qs)
	})

	// ГЛАГОЛ БЕЗ ЗАПУСКАТЕЛЯ. Ось заведена не из осторожности: гейт нашёл на
	// себе самом ровно такую ложную находку — утверждение пробы, где слово
	// `merge-base` есть, а git нет.
	t.Run("глагол вне запускателя — не вызов, и это СОСЧИТАНО", func(t *testing.T) {
		src := []byte("package p\n\nimport \"testing\"\n\n" +
			"func f(t *testing.T, got string) {\n" +
			"\trequire.Contains(t, got, \"merge-base\")\n" +
			"\trequire.Contains(t, got, \"rev-list\", \"HEAD\")\n}\n")
		qs, c := scanOne(t, "internal/x/d_test.go", src)
		require.Zerof(t, c.Questions, "утверждение пробы прочитано как запуск git: %v", qs)
		require.Equal(t, 2, c.VerbOutsideRunner,
			"отсечённые вызовы не сосчитаны — тогда сужение до запускателя невидимо, и "+
				"«ноль находок» неотличимо от «сузили до нуля»")
	})

	// ЗАПУСКАТЕЛЬ БЕЗ `git` СРЕДИ ЛИТЕРАЛОВ. Тем же вызовом запускают tar и go.
	t.Run("exec.Command не про git — не вызов git", func(t *testing.T) {
		_, c := scanOne(t, "internal/x/e.go", goSource(
			`cmd := exec.Command("go", "test", "-run", "TestLog", "HEAD")`))
		require.Zero(t, c.Questions)
	})

	// ГЛАГОЛЫ, ВОПРОСА ОБ ИСТОРИИ НЕ ЗАДАЮЩИЕ. Молчание здесь — не пропуск, а
	// граница предмета, и она объявлена в шапке разбора.
	t.Run("не вопрос об истории: корень, провенанс, состав", func(t *testing.T) {
		for _, body := range []string{
			`cmd := exec.Command("git", "rev-parse", "--show-toplevel")`,
			`cmd := exec.Command("git", "rev-parse", "HEAD")`,
			`cmd := exec.Command("git", "ls-tree", "-r", "--name-only", "HEAD")`,
			`cmd := exec.Command("git", "show", "HEAD:go.mod")`,
			`cmd := exec.Command("git", "status", "--porcelain")`,
			`cmd := exec.Command("git", "cat-file", "blob", "HEAD:go.mod")`,
			`cmd := exec.Command("git", "diff", "--name-only", "HEAD")`,
		} {
			_, c := scanOne(t, "internal/x/a.go", goSource(body))
			require.Zerof(t, c.Questions, "прочитан как вопрос об истории: %s", body)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// ДОВОД ВЕДОМОСТИ, ЗАМЕРЕННЫЙ НА СИНТЕТИКЕ — И ИСПРАВЛЕННЫЙ ЗАМЕРОМ
//
// Запись `acceptance_edit_after_verdict.go#log` прощает вершину УМОЛЧАНИЯ. Её
// первая редакция стояла на утверждении «схлопывание переносит оба операнда одним
// коммитом, поэтому вердикт СОХРАНЯЕТСЯ». Замер ниже это утверждение ОПРОВЕРГ:
// документ, рождённый той же полосой, после схлопывания получает одну отметку на
// оба операнда, и находка исчезает.
//
// Верное утверждение уже, и оно ровно о том, чего боится задача #63: вердикт
// портится ТОЛЬКО в безопасную сторону. Красное полосы может стать зелёным
// ствола (документ родился на ней) — но ЗЕЛЁНОЕ ПОЛОСЫ КРАСНЫМ СТВОЛА НЕ
// СТАНОВИТСЯ НИ В ОДНОЙ из трёх посадок, потому что схлопывание двигает оба
// операнда вместе либо оставляет обоих на месте.
//
// Три посадки, и каждая отличается от соседней ОДНИМ фактом: лежал ли документ в
// стволе до полосы · правлен ли он после объявления состояния.

// verdictAcrossSquash — вердикт «файл правлен позже строки состояния» на полосе
// и на стволе после схлопывания. Возвращает пару, чтобы вызывающий сравнивал
// ИСХОДЫ, а не отметки времени: отметки схлопывание меняет заведомо.
//
// docOnTrunk — лежал ли документ в стволе ДО полосы. Факт несущий: рождённый
// полосой документ схлопывается вместе со своей правкой, и оба операнда получают
// одну отметку.
func verdictAcrossSquash(t *testing.T, docOnTrunk, editedAfterState bool) (lane, trunk bool) {
	t.Helper()
	dir := t.TempDir()
	env := append(gitenv.Env(),
		"GIT_AUTHOR_NAME=probe", "GIT_AUTHOR_EMAIL=probe@invalid",
		"GIT_COMMITTER_NAME=probe", "GIT_COMMITTER_EMAIL=probe@invalid")
	git := func(args ...string) string {
		t.Helper()
		c := gitenv.Command(dir, args...)
		c.Env = env
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	write := func(name, body string) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
	}
	epoch := func(args ...string) string {
		t.Helper()
		c := gitenv.Command(dir, args...)
		c.Env = env
		out, err := c.Output()
		require.NoError(t, err)
		return strings.TrimSpace(strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0])
	}
	verdict := func() bool {
		stateAt := epoch("log", "-1", "--format=%ct", "-L", "1,1:a.md")
		fileAt := epoch("log", "-1", "--format=%ct", "--", "a.md")
		return fileAt > stateAt
	}

	git("init", "--quiet", "-b", "main", ".")
	write("z.txt", "заглушка\n")
	git("add", "z.txt")
	if docOnTrunk {
		write("a.md", "**Статус:** APPROVED\nтело\n")
		git("add", "a.md")
	}
	git("commit", "--quiet", "-m", "основание")

	git("checkout", "--quiet", "-b", "lane")
	if !docOnTrunk {
		write("a.md", "**Статус:** APPROVED\nтело\n")
		git("add", "a.md")
		git("commit", "--quiet", "-m", "приёмка")
	}
	if editedAfterState {
		// ВТОРОЙ факт пары: правка ПОСЛЕ объявления состояния, отдельным
		// коммитом. Строка состояния при этом не трогается.
		waitForNextSecond(t, git)
		write("a.md", "**Статус:** APPROVED\nтело\nдописано после вердикта\n")
		git("commit", "--quiet", "-am", "правка после вердикта")
	}
	lane = verdict()

	git("checkout", "--quiet", "main")
	git("merge", "--quiet", "--squash", "lane")
	waitForNextSecond(t, git)
	git("commit", "--quiet", "-m", "схлопнуто из lane")
	trunk = verdict()
	return lane, trunk
}

// waitForNextSecond — отметка коммита в git имеет разрешение в СЕКУНДУ, и без
// сдвига два коммита получают одну отметку: пара «правлено позже» перестала бы
// различать что-либо, и молчание пробы было бы свойством часов, а не git.
func waitForNextSecond(t *testing.T, git func(args ...string) string) {
	t.Helper()
	before := git("log", "-1", "--format=%ct")
	for i := 0; i < 200; i++ {
		if out, err := exec.Command("date", "+%s").Output(); err == nil &&
			strings.TrimSpace(string(out)) != before {
			return
		}
		sleepTick()
	}
	t.Fatal("проба НЕ ИСПОЛНЯЛАСЬ: секунда не сменилась за отведённые попытки")
}

// TestSquashNeverTurnsAGreenLaneIntoARedTrunk — ЗАМЕР ДОВОДА ВЕДОМОСТИ.
//
// Утверждается НЕ «вердикт сохраняется» (это опровергнуто второй посадкой), а
// то единственное, чего требует задача #63: зелёное полосы не становится красным
// ствола. Третья посадка — положительный контроль: без неё «зелено везде»
// зеленело бы и на предикате, который не находит ничего вовсе.
func TestSquashNeverTurnsAGreenLaneIntoARedTrunk(t *testing.T) {
	t.Parallel()

	for _, c := range []struct {
		name                    string
		docOnTrunk, editedAfter bool
		wantLane, wantTrunk     bool
	}{
		{"документ лежал в стволе, правлен после вердикта", true, true, true, true},
		{"документ рождён полосой и правлен после вердикта", false, true, true, false},
		{"приёмка одним коммитом — правки после вердикта нет", false, false, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			lane, trunk := verdictAcrossSquash(t, c.docOnTrunk, c.editedAfter)
			require.Equalf(t, c.wantLane, lane, "вердикт НА ПОЛОСЕ разошёлся с объявленным")
			require.Equalf(t, c.wantTrunk, trunk, "вердикт НА СТВОЛЕ после схлопывания разошёлся с объявленным")
			require.Falsef(t, !lane && trunk,
				"ЗЕЛЁНОЕ ПОЛОСЫ СТАЛО КРАСНЫМ СТВОЛА — ровно тот класс, ради которого заведена "+
					"задача #63. Тогда довод ведомости `acceptance_edit_after_verdict.go#log` "+
					"неверен, и вершину умолчания прощать нечем")
		})
	}
}

// sleepTick — короткая пауза между опросами часов. Вынесена ради одного
// импорта: `time` нужен только здесь.
func sleepTick() { time.Sleep(10 * time.Millisecond) }
